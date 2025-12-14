use homedir::get_my_home;
use std::env;
#[allow(unused_imports)]
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use is_executable::IsExecutable;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    // println!("Logs from your program will appear here!");
    let mut current_path = env::current_dir().unwrap();
    let path = env::var("PATH").unwrap_or_default();
    let path: Vec<PathBuf> = path.trim().split(":").map(|s| s.into()).collect();
    // println!("{:?}", path);

    let built_in = vec!["echo", "exit", "type", "pwd", "cd"];

    // Uncomment this block to pass the first stage
    loop {
        print!("$ ");
        io::stdout().flush().unwrap();

        // Wait for user input
        let stdin = io::stdin();
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        match spilt_input(&input) {
            Ok(vec) => {
                if vec.is_empty() {
                    continue;
                }
                match vec[0] {
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
                            let mut command = Command::new(cmd);
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
fn spilt_input(input: &str) -> Result<Vec<&str>, String> {
    let mut data = input.trim();
    if !data.contains('\'') {
        return Ok(data.split_whitespace().collect());
    }

    let mut vec = Vec::new();
    // exact cmd
    if let Some((i, _)) = data.char_indices().find(|(_, ch)| ch.is_whitespace()) {
        vec.push(data[..i].trim());
        data = &data[i + 1..].trim();
        // println!("cmd: {}", vec[0]);
        // println!("args: {}", data);
    }

    while !data.is_empty() {
        if let Some((l, _)) = data.char_indices().find(|(_, ch)| *ch == '\'') {
            if l > 0 {
                let temp = data[..l].trim();
                temp.split_whitespace().for_each(|s| vec.push(s));
            }

            if let Some((r, _)) = data.char_indices().skip(l + 1).find(|(_, ch)| *ch == '\'') {
                // println!("{l} -> {r}");
                if r - l == 1 {
                    data = &data[r + 1..];
                } else {
                    vec.push(&data[l + 1..r]);
                    data = &data[r + 1..];
                }
            } else {
                let error = format!(
                    r#"
single quote not matched:
input:    [{input}]
error on: [{}]"#,
                    &data[l..]
                );
                return Err(error);
            }
        } else {
            data.split_whitespace().for_each(|s| vec.push(s));
            break;
        }
    }

    Ok(vec)
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
