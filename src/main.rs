use anyhow::Result;
use crossterm::event::{read, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm::{cursor, execute};
use homedir::get_my_home;
use is_executable::IsExecutable;
use std::cmp::{max, min};
use std::env;
use std::io::Stdout;
#[allow(unused_imports)]
use std::io::{self, stdout, Write};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

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

    loop {
        print!("$ ");
        stdout().flush().unwrap();

        // Wait for user input
        let input = read_line_crossterm(&records).unwrap();
        if input.is_empty() {
            continue;
        }

        match spilt_input(&input) {
            Ok(vec) => {
                let vec = vec.iter().map(String::as_str).collect::<Vec<_>>();
                if vec.is_empty() {
                    continue;
                } else {
                    records.push(input.trim().to_string());
                }

                if vec.len() > 2 && vec[vec.len() - 2].contains('<') {}

                match vec[0] {
                    "history" => {
                        let mut skip = 0;
                        if vec.len() > 1
                            && let Ok(n) = vec[1].parse::<usize>()
                        {
                            skip = max(records.len() - n, 0);
                        };

                        for (i, cmd) in records.iter().enumerate().skip(skip) {
                            println!("{}  {cmd}", i + 1);
                        }
                    }
                    "exit" => {
                        break;
                    }
                    "cd" => {
                        let new_path = vec[1];
                        if new_path == "~" {
                            current_path = get_my_home().unwrap().unwrap();
                        } else if new_path.starts_with("/") {
                            match PathBuf::from_str(new_path) {
                                Ok(new_path) => {
                                    current_path = real_path(new_path, current_path);
                                }
                                Err(_) => {
                                    println!("cd: {new_path}: No such file or directory");
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
                        println!("{}", vec[1..].join(" "))
                    }
                    "type" => {
                        if vec.len() < 2 {
                            eprintln!("no argument after type");
                            continue;
                        }

                        if built_in.contains(&vec[1]) {
                            println!("{} is a shell builtin", vec[1]);
                        } else {
                            match find(&path, vec[1].to_string().clone()) {
                                None => {
                                    // should be:
                                    // println!("{}: command not found", vec[1]);
                                    println!("{}: not found", vec[1]);
                                }
                                Some(cmd) => {
                                    println!("{} is {}", vec[1], cmd)
                                }
                            }
                        }
                    }
                    _cmd => match find(&path, _cmd.to_string()) {
                        None => {
                            println!("{}: command not found", vec[0]);
                        }
                        Some(cmd) => {
                            if cmd.trim().is_empty() {
                                continue;
                            }
                            let mut command = Command::new(_cmd);
                            command.current_dir(current_path.clone());
                            vec[1..].iter().for_each(|arg| {
                                command.arg(arg);
                            });
                            let x = command.output();
                            print!("{}", String::from_utf8_lossy(x.unwrap().stdout.as_slice()));
                        }
                    },
                }
            }
            Err(err) => {
                eprintln!("{err}");
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
        println!(
            "cd: {}: No such file or directory",
            new_path.to_str().unwrap()
        );
        current_path
    }
}

// one-line cmd only
fn spilt_input(input: &str) -> Result<Vec<String>> {
    let data = input.trim();

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

    push_str_and_clear(&mut current, &mut vec);

    Ok(vec)
}

fn push_str_and_clear(string: &mut String, vec: &mut Vec<String>) {
    if !string.is_empty() {
        vec.push(string.clone());
        string.clear();
    }
}

fn read_line_crossterm(history: &Vec<String>) -> Result<String> {
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
        let r = spilt_input(src)?;
        // print!("{r:?}");
        assert_eq!(
            r,
            res.iter().map(|s| s.to_string()).collect::<Vec<String>>()
        );
        println!("  passed");
    }

    Ok(())
}
