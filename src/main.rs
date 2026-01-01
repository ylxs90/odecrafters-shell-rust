use crate::ExecResult::{Continue, Exit};
use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyModifiers, read};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm::{cursor, execute};
use is_executable::IsExecutable;
use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, close, dup2, execvp, fork, pipe};
use std::cmp::{max, min};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{OpenOptions, read_dir, read_to_string};
use std::io::Stdout;
#[allow(unused_imports)]
use std::io::{self, Write, stdout};
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::string::ToString;
use std::{env, fs};


const BUILT_IN: &[&str] = &["echo", "exit", "type", "pwd", "cd", "history"];

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    // println!("Logs from your program will appear here!");
    let path = env::var("PATH").unwrap_or_default();
    let path: Vec<PathBuf> = path
        .trim()
        .split(":")
        .filter(|s| !s.starts_with("/mnt/c"))
        .map(|s| s.into())
        .collect();
    // println!("{:?}", path);

    let mut records: Vec<String> = Vec::new();
    // Uncomment this block to pass the first stage
    let mut cmd_list = vec![];

    BUILT_IN.iter().map(|s| s.to_string()).for_each(|s| {
        cmd_list.push(s.clone());
    });
    // path.iter().for_each(|p| println!("{p:?}"));

    // let now = Instant::now();
    build_complete_dictionary(&path)
        .unwrap_or_default()
        .iter()
        .for_each(|c| {
            cmd_list.push(c.to_string());
        });

    let history_file = env::var("HISTFILE");
    match history_file.clone() {
        Ok(history_file) => {
            read_to_string(history_file)
                .unwrap()
                .lines()
                .filter(|l| !l.is_empty())
                .for_each(|l| records.push(l.trim().to_string()));
        }
        _ => {}
    }

    loop {
        print!("$ ");
        stdout().flush().unwrap();

        // Wait for user input
        let input = read_line_crossterm(&records, &cmd_list).unwrap();
        if input.is_empty() {
            continue;
        }

        match spilt_input(&input) {
            Ok(tokens) => {
                records.push(input.trim().to_string());
                match AstNode::try_from(tokens) {
                    Ok(node) => match node {
                        AstNode::Command(cmd) => {
                            let saved_fds = apply_redirects(&cmd.redirects).unwrap();
                            let result = execute_cmd(cmd, &mut records, &history_file, &path);
                            restore_redirects(&saved_fds).unwrap();

                            match result {
                                Continue => continue,
                                Exit => break,
                            }
                        }
                        AstNode::Pipeline(cmds) => {
                            let len = cmds.len();
                            if len > 2 {
                                eprintln!("error: only support two commands in pipeline");
                                continue;
                            }

                            let (read_fd, write_fd) = pipe().unwrap();

                            match unsafe { fork().unwrap() } {
                                ForkResult::Child => {
                                    let cmd = cmds[0].clone();
                                    // child process: first command
                                    dup2(write_fd, 1).unwrap(); // redirect stdout to pipe write end
                                    close(read_fd).unwrap();
                                    close(write_fd).unwrap();
                                    let argv = &cmd.argv[1..];
                                    if cmd.is_built_in() {
                                        match cmd.command().as_str() {
                                            "history" => {
                                                if argv.len() > 2 {
                                                    match argv[1].as_str() {
                                                        "-r" => read_to_string(&argv[2])
                                                            .unwrap()
                                                            .lines()
                                                            .filter(|l| !l.is_empty())
                                                            .for_each(|l| {
                                                                records.push(l.trim().to_string())
                                                            }),
                                                        "-w" => {
                                                            let mut history = records.join("\n");
                                                            history.push('\n');
                                                            fs::write(&argv[2], history).unwrap();
                                                        }
                                                        "-a" => {
                                                            let mut file = OpenOptions::new()
                                                                .append(true)
                                                                .open(&argv[2])
                                                                .unwrap();
                                                            let mut history = records.join("\n");
                                                            history.push('\n');
                                                            write!(file, "{}", history).unwrap();
                                                            records.clear();
                                                        }
                                                        _ => {}
                                                    }
                                                    continue;
                                                }

                                                let mut skip = 0;
                                                if argv.len() > 1
                                                    && let Ok(n) = argv[1].parse::<usize>()
                                                {
                                                    skip = max(records.len() - n, 0);
                                                }

                                                for (i, cmd) in
                                                    records.iter().enumerate().skip(skip)
                                                {
                                                    println!("{}  {cmd}", i + 1);
                                                }
                                            }
                                            "exit" => {
                                                match history_file {
                                                    Ok(history_file) => {
                                                        let mut history = records.join("\n");
                                                        history.push('\n');
                                                        fs::write(history_file, history).unwrap();
                                                    }
                                                    Err(_) => {}
                                                }
                                                break;
                                            }
                                            "cd" => {
                                                let new_path = argv[1].clone();
                                                if new_path == "~" {
                                                    env::set_current_dir(env::home_dir().unwrap())
                                                        .unwrap();
                                                } else if new_path.starts_with("/") {
                                                    match env::set_current_dir(new_path.clone()) {
                                                        Ok(_) => {}
                                                        Err(_) => {
                                                            eprintln!(
                                                                "cd: {new_path}: No such file or directory"
                                                            );
                                                        }
                                                    };
                                                } else {
                                                    let mut temp = env::current_dir().unwrap();
                                                    temp.push(new_path.clone());
                                                    match env::set_current_dir(temp) {
                                                        Ok(_) => {}
                                                        Err(_) => {
                                                            eprintln!(
                                                                "cd: {new_path}: No such file or directory"
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            "pwd" => {
                                                println!(
                                                    "{}",
                                                    env::current_dir().unwrap().to_str().unwrap()
                                                );
                                            }
                                            "echo" => {
                                                println!("{}", argv[1..].join(" "))
                                            }
                                            "type" => {
                                                if argv.len() < 2 {
                                                    eprintln!("no argument after type");
                                                    continue;
                                                }

                                                println!("{} is a shell builtin", argv[1]);
                                            }
                                            _ => {}
                                        }
                                    } else {
                                        let x: Vec<CString> = cmd
                                            .argv
                                            .iter()
                                            .map(|s| CString::from_str(s).unwrap())
                                            .collect();

                                        let c = CString::from_str(cmd.command().as_str()).unwrap();
                                        execvp(&c, &x).unwrap();
                                    }

                                    unreachable!();
                                }
                                _ => {}
                            }

                            match unsafe { fork().unwrap() } {
                                ForkResult::Child => {
                                    let cmd = cmds[1].clone();

                                    // child process: first command
                                    dup2(read_fd, 0).unwrap(); // redirect stdout to pipe write end
                                    close(write_fd).unwrap();
                                    let argv = &cmd.argv[1..];
                                    if cmd.is_built_in() {
                                        match cmd.command().as_str() {
                                            "history" => {
                                                if argv.len() > 2 {
                                                    match argv[1].as_str() {
                                                        "-r" => read_to_string(&argv[2])
                                                            .unwrap()
                                                            .lines()
                                                            .filter(|l| !l.is_empty())
                                                            .for_each(|l| {
                                                                records.push(l.trim().to_string())
                                                            }),
                                                        "-w" => {
                                                            let mut history = records.join("\n");
                                                            history.push('\n');
                                                            fs::write(&argv[2], history).unwrap();
                                                        }
                                                        "-a" => {
                                                            let mut file = OpenOptions::new()
                                                                .append(true)
                                                                .open(&argv[2])
                                                                .unwrap();
                                                            let mut history = records.join("\n");
                                                            history.push('\n');
                                                            write!(file, "{}", history).unwrap();
                                                            records.clear();
                                                        }
                                                        _ => {}
                                                    }
                                                    continue;
                                                }

                                                let mut skip = 0;
                                                if argv.len() > 1
                                                    && let Ok(n) = argv[1].parse::<usize>()
                                                {
                                                    skip = max(records.len() - n, 0);
                                                }

                                                for (i, cmd) in
                                                    records.iter().enumerate().skip(skip)
                                                {
                                                    println!("{}  {cmd}", i + 1);
                                                }
                                            }
                                            "exit" => {
                                                match history_file {
                                                    Ok(history_file) => {
                                                        let mut history = records.join("\n");
                                                        history.push('\n');
                                                        fs::write(history_file, history).unwrap();
                                                    }
                                                    Err(_) => {}
                                                }
                                                break;
                                            }
                                            "cd" => {
                                                let new_path = argv[1].clone();
                                                if new_path == "~" {
                                                    env::set_current_dir(env::home_dir().unwrap())
                                                        .unwrap();
                                                } else if new_path.starts_with("/") {
                                                    match env::set_current_dir(new_path.clone()) {
                                                        Ok(_) => {}
                                                        Err(_) => {
                                                            eprintln!(
                                                                "cd: {new_path}: No such file or directory"
                                                            );
                                                        }
                                                    };
                                                } else {
                                                    let mut temp = env::current_dir().unwrap();
                                                    temp.push(new_path.clone());
                                                    match env::set_current_dir(temp) {
                                                        Ok(_) => {}
                                                        Err(_) => {
                                                            eprintln!(
                                                                "cd: {new_path}: No such file or directory"
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            "pwd" => {
                                                println!(
                                                    "{}",
                                                    env::current_dir().unwrap().to_str().unwrap()
                                                );
                                            }
                                            "echo" => {
                                                println!("{}", argv[1..].join(" "))
                                            }
                                            "type" => {
                                                if argv.len() < 2 {
                                                    eprintln!("no argument after type");
                                                    continue;
                                                }

                                                println!("{} is a shell builtin", argv[1]);
                                            }
                                            _ => {}
                                        }
                                    } else {
                                        let x: Vec<CString> = cmd
                                            .argv
                                            .iter()
                                            .map(|s| CString::from_str(s).unwrap())
                                            .collect();

                                        let c = CString::from_str(cmd.command().as_str()).unwrap();
                                        execvp(&c, &x).unwrap();
                                    }

                                    unreachable!();
                                }
                                _ => {}
                            }

                            close(read_fd).unwrap();
                            close(write_fd).unwrap();

                            for _ in 0..cmds.len() {
                                waitpid(None, None).unwrap();
                            }

                            continue;
                        }
                    },
                    Err(_) => continue,
                }
            }
            Err(e) => {
                eprintln!("error: {}", e);
            }
        }
    }
}
enum ExecResult {
    Continue,
    Exit,
}

fn execute_cmd(
    cmd: CommandSpec,
    records: &mut Vec<String>,
    history_file: &Result<String, std::env::VarError>,
    path: &Vec<PathBuf>,
) -> ExecResult {
    let saved_fds = match apply_redirects(&cmd.redirects) {
        Err(e) => {
            eprint!("{}", e);
            return Continue;
        }
        Ok(saved_fds) => saved_fds,
    };
    let argv = cmd.argv.iter().map(String::as_str).collect::<Vec<_>>();
    if argv.is_empty() {
        return Continue;
    }

    match cmd.command().as_str() {
        "history" => {
            if argv.len() > 2 {
                match argv[1] {
                    "-r" => read_to_string(argv[2])
                        .unwrap()
                        .lines()
                        .filter(|l| !l.is_empty())
                        .for_each(|l| records.push(l.trim().to_string())),
                    "-w" => {
                        let mut history = records.join("\n");
                        history.push('\n');
                        fs::write(argv[2], history).unwrap();
                    }
                    "-a" => {
                        let mut file = OpenOptions::new().append(true).open(argv[2]).unwrap();
                        let mut history = records.join("\n");
                        history.push('\n');
                        write!(file, "{}", history).unwrap();
                        records.clear();
                    }
                    _ => {}
                }
                return Continue;
            }

            let mut skip = 0;
            if argv.len() > 1
                && let Ok(n) = argv[1].parse::<usize>()
            {
                skip = max(records.len() - n, 0);
            }

            for (i, cmd) in records.iter().enumerate().skip(skip) {
                println!("{}  {cmd}", i + 1);
            }
        }
        "exit" => {
            match history_file {
                Ok(history_file) => {
                    let mut history = records.join("\n");
                    history.push('\n');
                    fs::write(history_file, history).unwrap();
                }
                Err(_) => {}
            }
            return Exit;
        }
        "cd" => {
            let new_path = argv[1];
            if new_path == "~" {
                env::set_current_dir(env::home_dir().unwrap()).unwrap();
            } else if new_path.starts_with("/") {
                match env::set_current_dir(new_path) {
                    Ok(_) => {}
                    Err(_) => {
                        eprintln!("cd: {new_path}: No such file or directory");
                    }
                };
            } else {
                let mut temp = env::current_dir().unwrap();
                temp.push(new_path);
                match env::set_current_dir(temp) {
                    Ok(_) => {}
                    Err(_) => {
                        eprintln!("cd: {new_path}: No such file or directory");
                    }
                }
            }
        }
        "pwd" => {
            println!("{}", env::current_dir().unwrap().to_str().unwrap());
        }
        "echo" => {
            println!("{}", argv[1..].join(" "))
        }
        "type" => {
            if argv.len() < 2 {
                eprintln!("no argument after type");
                return Continue;
            }

            if BUILT_IN.contains(&argv[1]) {
                println!("{} is a shell builtin", argv[1]);
            } else {
                match find(&path, argv[1].to_string().clone()) {
                    None => {
                        // should be:
                        // println!("{}: command not found", vec[1]);
                        eprintln!("{}: not found", argv[1]);
                    }
                    Some(cmd) => {
                        println!("{} is {}", argv[1], cmd)
                    }
                }
            }
        }
        _cmd => match find(&path, _cmd.to_string()) {
            None => {
                eprintln!("{}: command not found", argv[0]);
            }
            Some(cmd) => {
                if cmd.trim().is_empty() {
                    return Continue;
                }
                let mut command = Command::new(_cmd);
                // command.current_dir(current_path.clone());
                argv[1..].iter().for_each(|arg| {
                    command.arg(arg);
                });
                let x = command.output();
                let output = x.unwrap();
                print!("{}", String::from_utf8_lossy(output.stdout.as_slice()));
                eprint!("{}", String::from_utf8_lossy(output.stderr.as_slice()));
            }
        },
    }

    restore_redirects(&saved_fds).unwrap();

    Continue
}

fn find(paths: &Vec<PathBuf>, cmd: String) -> Option<String> {
    for path in paths {
        let mut path = path.clone();
        path.push(cmd.as_str());
        if path.is_file() && path.is_executable() {
            return Some(path.to_str().unwrap().to_string());
        }
    }
    None
}

#[allow(unused)]
fn real_path(new_path: PathBuf, current_path: PathBuf) -> PathBuf {
    if new_path.is_file() || new_path.is_dir() {
        new_path.canonicalize().unwrap()
    } else {
        eprintln!(
            "cd: {}: No such file or directory",
            new_path.to_str().unwrap()
        );
        current_path
    }
}

// one-line cmd only
fn spilt_input(input: &str) -> Result<Vec<String>, String> {
    let data = input.trim();

    #[derive(Eq, PartialEq)]
    enum Mode {
        Normal,
        InSingleQuote,
        InDoubleQuote,
        Escape,
    }

    let mut state = Mode::Normal;
    let mut chars = data.chars().peekable();
    let mut current = String::new();
    let mut vec = Vec::new();

    while let Some(c) = chars.next() {
        // println!("{current}");
        match state {
            Mode::Normal => match c {
                '\'' => {
                    if chars.next_if(|c| *c == '\'').is_none() {
                        state = Mode::InSingleQuote;
                    }
                }
                '\"' => {
                    if chars.next_if(|c| *c == '\"').is_none() {
                        state = Mode::InDoubleQuote;
                    }
                }
                ' ' | '\t' => {
                    push_str_and_clear(&mut current, &mut vec);
                }
                '\\' => {
                    state = Mode::Escape;
                }
                '|' => {
                    push_str_and_clear(&mut current, &mut vec);
                    vec.push("|".to_string());
                }
                _ => current.push(c),
            },
            Mode::InSingleQuote => match c {
                '\'' => {
                    if chars.next_if(|c| *c == '\'').is_none() {
                        state = Mode::Normal;
                    }
                }
                _ => {
                    current.push(c);
                }
            },
            Mode::InDoubleQuote => match c {
                '\"' => {
                    if chars.next_if(|c| *c == '\"').is_none() {
                        state = Mode::Normal;
                    }
                }
                '\\' => {
                    if let Some(ch) = chars.next_if(|ch| ['$', '\\', '"'].contains(ch)) {
                        current.push(ch);
                    } else {
                        current.push(c);
                    }
                }
                _ => {
                    current.push(c);
                }
            },
            Mode::Escape => {
                current.push(c);
                state = Mode::Normal;
            }
        }
    }

    if state != Mode::Normal {
        return Err("cmd invalid".to_string());
    }

    push_str_and_clear(&mut current, &mut vec);

    Ok(vec)
}

fn apply_redirects(redirects: &[Redirect]) -> Result<Vec<(RawFd, RawFd)>, String> {
    let mut vec = Vec::new();
    for redirect in redirects {
        let f = if PathBuf::from(&redirect.target).is_absolute() {
            let mut f = env::current_dir().unwrap();
            f.push(&redirect.target);
            f
        } else {
            PathBuf::from(&redirect.target)
        };

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(redirect.mode == RedirectOp::Append)
            .truncate(redirect.mode == RedirectOp::Write)
            .open(f)
            .map_err(|e| format!("{}: {}", redirect.target, e))?;
        let fd = redirect.fd;
        unsafe {
            let saved_fd = libc::dup(fd);
            if saved_fd < 0 {
                return Err(format!("dup failed for fd {}", fd));
            }
            libc::dup2(file.as_raw_fd(), fd);
            vec.push((fd, saved_fd));
        }
    }

    Ok(vec)
}

fn restore_redirects(saved_fds: &[(RawFd, RawFd)]) -> Result<(), String> {
    for (current, saved) in saved_fds {
        unsafe {
            libc::dup2(*saved, *current);
            libc::close(*saved);
        }
    }

    Ok(())
}

fn push_str_and_clear(string: &mut String, vec: &mut Vec<String>) {
    if !string.trim().is_empty() {
        vec.push(string.clone());
        string.clear();
    }
}

fn read_line_crossterm(history: &[String], cmd_list: &[String]) -> Result<String> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    let mut buffer = String::new();
    let mut i: i32 = history.len() as i32;
    let mut is_last_tab_pressed = false;
    loop {
        match read()? {
            Event::Key(event) => {
                if event.code != KeyCode::Tab {
                    is_last_tab_pressed = false;
                }

                match event.code {
                    KeyCode::Char(c) => {
                        if event.modifiers == KeyModifiers::CONTROL && c == 'c' {
                            println!(" ^C");
                            disable_raw_mode()?;
                            std::process::exit(0);
                        } else if event.modifiers == KeyModifiers::CONTROL && c == 'j' {
                            // ctrl + j acts Enter in bash/zsh
                            print!("\r\n");
                            break;
                        } else {
                            buffer.push(c);
                            print!("{}", c);
                            stdout.flush()?;
                        }
                    }
                    KeyCode::Backspace => {
                        if !buffer.is_empty() {
                            buffer.pop();
                            print!("\x08 \x08");
                            stdout.flush()?;
                        }
                    }
                    KeyCode::Enter => {
                        print!("\r\n");
                        break;
                    }
                    KeyCode::Up => {
                        if history.is_empty() {
                            continue;
                        }
                        i = max(0, i - 1);

                        if let Some(cmd) = history.iter().nth(i as usize) {
                            replace_line(&mut buffer, cmd, &mut stdout)?;
                        }
                    }
                    KeyCode::Down => {
                        if history.is_empty() {
                            continue;
                        }
                        i = min(history.len() as i32 - 1, i + 1);

                        if let Some(cmd) = history.iter().nth(i as usize) {
                            replace_line(&mut buffer, cmd, &mut stdout)?;
                        }
                    }
                    KeyCode::Left | KeyCode::Right => {}
                    KeyCode::Tab => {
                        let mut matched_list: HashSet<&String> = HashSet::new();
                        cmd_list
                            .iter()
                            .filter(|c| c.starts_with(&buffer))
                            .for_each(|c| {
                                matched_list.insert(c);
                            });

                        if matched_list.is_empty() {
                            print!("{}", '\x07');
                            stdout.flush()?;
                        } else {
                            let mut matched_list: Vec<&String> =
                                matched_list.iter().map(|s| *s).collect();
                            let cmd = longest_common_prefix(&matched_list);
                            if buffer != cmd {
                                replace_line(
                                    &mut buffer,
                                    &format!(
                                        "{cmd}{}",
                                        if matched_list.len() == 1 { " " } else { "" }
                                    ),
                                    &mut stdout,
                                )?;
                            } else {
                                if is_last_tab_pressed {
                                    matched_list.sort();
                                    let mut iter = matched_list.iter().peekable();
                                    let mut list = String::new();
                                    iter.clone().for_each(|s| {
                                        list.push_str(s);
                                        if iter.peek().is_some() {
                                            list.push_str("  ");
                                        }
                                    });
                                    print!("\r\n{list}\r\n$ {buffer}");
                                    stdout.flush()?;
                                } else {
                                    print!("\x07");
                                    stdout.flush()?;
                                    is_last_tab_pressed = true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    disable_raw_mode()?;
    Ok(buffer)
}

fn replace_line(buffer: &mut String, cmd: &String, stdout: &mut Stdout) -> Result<()> {
    buffer.clear();
    buffer.push_str(cmd.as_str());
    execute!(
        stdout,
        cursor::MoveToColumn(0),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine)
    )?;
    print!("$ {cmd}");
    stdout.flush()?;
    Ok(())
}

fn longest_common_prefix(items: &[&String]) -> String {
    if items.is_empty() {
        return String::new();
    }

    let mut prefix = items[0].clone();

    for s in &items[1..] {
        let mut i = 0;
        let max = prefix.len().min(s.len());

        while i < max && prefix.as_bytes()[i] == s.as_bytes()[i] {
            i += 1;
        }

        prefix.truncate(i);

        if prefix.is_empty() {
            break;
        }
    }

    prefix
}

#[derive(Debug, Default, Clone)]
struct CommandSpec {
    argv: Vec<String>,
    redirects: Vec<Redirect>,
}

impl CommandSpec {
    pub fn command(&self) -> String {
        self.argv[0].clone()
    }

    pub fn is_built_in(&self) -> bool {
        BUILT_IN.contains(&self.command().as_str())
    }
}

impl TryFrom<Vec<String>> for AstNode {
    type Error = String;

    fn try_from(value: Vec<String>) -> std::result::Result<Self, Self::Error> {
        if value.iter().any(|s| "|".eq(s)) {
            let mut cmds = vec![];
            for cmd in value.split(|s| "|".eq(s)) {
                cmds.push(CommandSpec::try_from(cmd.to_vec())?);
            }
            Ok(AstNode::Pipeline(cmds))
        } else {
            Ok(AstNode::Command(CommandSpec::try_from(value)?))
        }
    }
}
impl TryFrom<Vec<String>> for CommandSpec {
    type Error = String;

    fn try_from(value: Vec<String>) -> std::result::Result<Self, Self::Error> {
        if value.is_empty() {
            return Ok(Default::default());
        }

        let mut tokens = value.into_iter().peekable();
        let mut argv = Vec::new();
        let mut redirects = Vec::new();
        while let Some(token) = tokens.next() {
            match token.as_str() {
                ">" | ">>" | "1>" | "1>>" | "2>" | "2>>" => {
                    if let Some(target) = tokens.next() {
                        let redirect = match token.as_str() {
                            ">" | "1>" => Redirect {
                                target,
                                fd: 1,
                                mode: RedirectOp::Write,
                            },
                            ">>" | "1>>" => Redirect {
                                target,
                                fd: 1,
                                mode: RedirectOp::Append,
                            },
                            "2>" => Redirect {
                                target,
                                fd: 2,
                                mode: RedirectOp::Write,
                            },
                            "2>>" => Redirect {
                                target,
                                fd: 2,
                                mode: RedirectOp::Append,
                            },
                            _ => {
                                return Err(format!("unexpected redirect token: {token}"));
                            }
                        };
                        redirects.push(redirect);
                    } else {
                        return Err(format!("missing target: {token}"));
                    }
                }
                _ => {
                    argv.push(token);
                }
            }
        }
        Ok(CommandSpec { argv, redirects })
    }
}

#[derive(Debug, Clone, Default)]
struct Redirect {
    fd: i32, // 0 stdin, 1 stdout, 2 stderr
    target: String,
    mode: RedirectOp,
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
enum RedirectOp {
    #[default]
    Write,
    Append,
}

#[allow(unused)]
#[derive(Debug)]
enum AstNode {
    Command(CommandSpec),
    Pipeline(Vec<CommandSpec>),
}

fn build_complete_dictionary(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    let mut cmds = Vec::new();

    for path in paths {
        match read_dir(&path) {
            Ok(dir) => dir.for_each(|c| match c {
                Ok(f) => {
                    let p = f.path();
                    if p.is_file() && p.is_executable() {
                        cmds.push(p.file_name().unwrap().to_str().unwrap().to_string());
                    }
                }
                Err(_) => {}
            }),
            Err(_) => {}
        }
    }
    Ok(cmds)
}

#[test]
fn test_find() {
    let paths: Vec<PathBuf> = vec!["/bin"].iter().map(|s| s.into()).collect();
    println!("{:?}", find(&paths, "cat".to_string()));
}

#[test]
fn test_execute() {
    use homedir::get_my_home;
    let mut command = Command::new("ls");
    command.arg("-l").arg("-a");
    let x = command.output();
    println!("{}", String::from_utf8_lossy(x.unwrap().stdout.as_slice()));

    println!("{}", env::current_dir().unwrap().to_str().unwrap());
    let mut path = env::current_dir().unwrap();
    path.push("..");
    println!("{:?}", path.canonicalize().unwrap());
    println!("{:?}", get_my_home().unwrap().unwrap());
}

#[test]
fn test_spilt_input() {
    let args = spilt_input("  echo 'hello    world' demo ni hao'nice to meet you' hxiao");
    match args {
        Ok(args) => {
            println!("{:?}", args);
        }
        Err(err) => {
            eprintln!("{}", err);
        }
    }

    let args = spilt_input("  echo hello'    'world");
    match args {
        Ok(args) => {
            println!("{:?}", args);
        }
        Err(err) => {
            eprintln!("{}", err);
        }
    }

    let args = spilt_input("  echo hello''world");
    match args {
        Ok(args) => {
            println!("{:?}", args);
        }
        Err(err) => {
            eprintln!("{}", err);
        }
    }

    let args = spilt_input("  echo 'hello''world'");
    match args {
        Ok(args) => {
            println!("{:?}", args);
        }
        Err(err) => {
            eprintln!("{}", err);
        }
    }

    let args = spilt_input("  echo 'hello''world' | cat /tmp/aa > bb.txt | c");
    match args {
        Ok(args) => {
            println!("{:?}", AstNode::try_from(args));
        }
        Err(err) => {
            eprintln!("{}", err);
        }
    }
}

#[test]
fn test_spilt_output() -> Result<()> {
    let tests = vec![
        ("  echo 'hello''world'", vec!["echo", "helloworld"]),
        (
            r#"echo "world  hello"  "test""shell"#,
            vec!["echo", "world  hello", "testshell"],
        ),
        (
            r#"echo world\ \ hello  test\nshello"#,
            vec!["echo", "world  hello", "testnshello"],
        ),
        (
            r#"echo "script'test'\\'shell""#,
            vec!["echo", r#"script'test'\'shell"#],
        ),
        (
            r#"echo "shell'world'\\'test""#,
            vec!["echo", r#"shell'world'\'test"#],
        ),
        (
            r#"echo "example\"insidequotes"shell\""#,
            vec!["echo", r#"example"insidequotesshell""#],
        ),
    ];

    for (i, (src, res)) in tests.iter().enumerate() {
        print!("test {:02}--> {src} ", i + 1);
        let r = spilt_input(src).unwrap();
        // print!("{r:?}");
        assert_eq!(
            r,
            res.iter().map(|s| s.to_string()).collect::<Vec<String>>()
        );
        println!("  passed");
    }

    Ok(())
}

#[test]
fn test_nix() -> Result<()> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    // ========== pipeline: 3 commands ==========
    // echo hello > /tmp/test.out | cat /tmp/test.out 2> /tmp/out.err | wc

    // ---------- pipe 1 ----------

    let (p1_read, p1_write) = pipe()?;

    match unsafe { fork()? } {
        ForkResult::Child => {
            // stdout -> pipe
            dup2(p1_write, 1)?;
            close(p1_read)?;
            close(p1_write)?;

            // > /tmp/test.out （覆盖 pipe）
            let out = open(
                "/tmp/test.out",
                OFlag::O_CREAT | OFlag::O_WRONLY | OFlag::O_TRUNC,
                Mode::from_bits_truncate(0o644),
            )?;
            dup2(out, 1)?;
            close(out)?;

            execvp(c"echo", &[c"echo", c"hello"])?;
            unreachable!();
        }
        ForkResult::Parent { .. } => {}
    }

    close(p1_write)?;

    // ---------- pipe 2 ----------
    let (p2_read, p2_write) = pipe()?;

    match unsafe { fork()? } {
        ForkResult::Child => {
            // stdin <- pipe1
            dup2(p1_read, 0)?;
            // stdout -> pipe2
            dup2(p2_write, 1)?;

            close(p1_read)?;
            close(p2_read)?;
            close(p2_write)?;

            // 2> /tmp/out.err
            let err = open(
                "/tmp/out.err",
                OFlag::O_CREAT | OFlag::O_WRONLY | OFlag::O_TRUNC,
                Mode::from_bits_truncate(0o644),
            )?;
            dup2(err, 2)?;
            close(err)?;

            env::set_current_dir("/tmp")?;
            unreachable!();
        }
        ForkResult::Parent { .. } => {}
    }

    close(p1_read)?;
    close(p2_write)?;

    // ---------- last command ----------
    match unsafe { fork()? } {
        ForkResult::Child => {
            // stdin <- pipe2
            dup2(p2_read, 0)?;
            close(p2_read)?;

            execvp(c"wc", &[c"wc"])?;
            unreachable!();
        }
        ForkResult::Parent { .. } => {}
    }

    close(p2_read)?;

    // ---------- wait ----------
    for _ in 0..3 {
        waitpid(None, None)?;
    }

    Ok(())
}

#[test]
fn test_pipe_with_cd() -> Result<()> {
    println!("{}", env::current_dir()?.to_str().unwrap());
    // cd /tmp | pwd

    let (p_read, p_write) = pipe()?;

    match unsafe { fork()? } {
        ForkResult::Parent { .. } => {}
        ForkResult::Child => {
            dup2(p_write, 1)?;
            close(p_write)?;
            close(p_read)?;
            env::set_current_dir("/tmp")?;
        }
    }
    println!("{}", env::current_dir()?.to_str().unwrap());
    match unsafe { fork()? } {
        ForkResult::Parent { .. } => {}
        ForkResult::Child => {
            dup2(p_read, 0)?;
            close(p_read)?;
            close(p_write)?;
            execvp(c"pwd", &[c"pwd"])?;
        }
    }

    for _ in 0..2 {
        waitpid(None, None)?;
    }
    println!("{}", env::current_dir()?.to_str().unwrap());

    Ok(())
}
