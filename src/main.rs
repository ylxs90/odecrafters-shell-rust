use anyhow::Result;
use crossterm::event::{read, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm::{cursor, execute};
use homedir::get_my_home;
use is_executable::IsExecutable;
use std::cmp::{max, min};
use std::fs::{read_to_string, OpenOptions};
use std::io::Stdout;
#[allow(unused_imports)]
use std::io::{self, stdout, Write};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::{env, fs};

use std::os::fd::{AsRawFd, RawFd};

mod trie;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    // println!("Logs from your program will appear here!");
    let mut current_path = env::current_dir().unwrap();
    let path = env::var("PATH").unwrap_or_default();
    let path: Vec<PathBuf> = path.trim().split(":").map(|s| s.into()).collect();
    // println!("{:?}", path);

    let built_in = vec!["echo", "exit", "type", "pwd", "cd", "history"];
    let mut records: Vec<String> = Vec::new();
    // Uncomment this block to pass the first stage

    let mut cmd_list: Vec<String> = built_in.iter().map(|s| s.to_string()).collect();

    build_complete_dictionary(&path)
        .unwrap_or_default()
        .iter()
        .for_each(|c| cmd_list.push(c.to_string()));

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
    let mut saved_fds = vec![];

    loop {
        restore_redirects(&saved_fds).unwrap();
        print!("$ ");
        stdout().flush().unwrap();

        // Wait for user input
        let input = read_line_crossterm(&records, &cmd_list).unwrap();
        if input.is_empty() {
            continue;
        }

        match spilt_input(&input) {
            Ok(tokens) => match CommandSpec::try_from(tokens) {
                Ok(cmd) => {
                    // println!("{:?}", cmd);
                    saved_fds = match apply_redirects(&cmd.redirects, &current_path) {
                        Err(e) => {
                            eprint!("{}", e);
                            continue;
                        }
                        Ok(saved_fds) => saved_fds,
                    };
                    let argv = cmd.argv.iter().map(String::as_str).collect::<Vec<_>>();
                    if argv.is_empty() {
                        continue;
                    } else {
                        records.push(input.trim().to_string());
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
                                        let mut file =
                                            OpenOptions::new().append(true).open(argv[2]).unwrap();
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
                            break;
                        }
                        "cd" => {
                            let new_path = argv[1];
                            if new_path == "~" {
                                current_path = get_my_home().unwrap().unwrap();
                            } else if new_path.starts_with("/") {
                                match PathBuf::from_str(new_path) {
                                    Ok(new_path) => {
                                        current_path = real_path(new_path, current_path);
                                    }
                                    Err(_) => {
                                        eprintln!("cd: {new_path}: No such file or directory");
                                    }
                                }
                            } else {
                                let mut temp = current_path.clone();
                                temp.push(new_path);
                                current_path = real_path(temp, current_path);
                            }
                        }
                        "pwd" => {
                            println!("{}", current_path.to_str().unwrap());
                        }
                        "echo" => {
                            println!("{}", argv[1..].join(" "))
                        }
                        "type" => {
                            if argv.len() < 2 {
                                eprintln!("no argument after type");
                                continue;
                            }

                            if built_in.contains(&argv[1]) {
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
                                    continue;
                                }
                                let mut command = Command::new(_cmd);
                                command.current_dir(current_path.clone());
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
                }
                Err(_) => continue,
            },
            Err(e) => {
                eprintln!("error: {}", e);
            }
        }
    }
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

fn apply_redirects(
    redirects: &[Redirect],
    current_dir: &PathBuf,
) -> Result<Vec<(RawFd, RawFd)>, String> {
    let mut vec = Vec::new();
    for redirect in redirects {
        let f = if PathBuf::from(&redirect.target).is_absolute() {
            let mut f = current_dir.clone();
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
    if !string.is_empty() {
        vec.push(string.clone());
        string.clear();
    }
}

fn read_line_crossterm(history: &[String], cmd_list: &[String]) -> Result<String> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    let mut buffer = String::new();
    let mut i: i32 = history.len() as i32;

    loop {
        match read()? {
            Event::Key(event) => match event.code {
                KeyCode::Char(c) => {
                    if event.modifiers == KeyModifiers::CONTROL && c == 'c' {
                        println!(" ^C");
                        disable_raw_mode()?;
                        std::process::exit(1);
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
                    if let Some(cmd) = cmd_list.iter().find(|c| c.starts_with(&buffer)) {
                        replace_line(&mut buffer, cmd, &mut stdout)?;
                    }
                }
                _ => {}
            },
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

#[derive(Debug, Default)]
struct CommandSpec {
    argv: Vec<String>,
    redirects: Vec<Redirect>,
}

impl CommandSpec {
    pub fn command(&self) -> String {
        self.argv[0].clone()
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
enum AstNode {
    Command(CommandSpec),
    Pipeline(Vec<CommandSpec>),
}

fn build_complete_dictionary(_paths: &[PathBuf]) -> Result<Vec<String>, String> {
    Ok(vec![])
}

#[test]
fn test_find() {
    let paths: Vec<PathBuf> = vec!["/bin"].iter().map(|s| s.into()).collect();
    println!("{:?}", find(&paths, "cat".to_string()));
}

#[test]
fn test_execute() {
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
