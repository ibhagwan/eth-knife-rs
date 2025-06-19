use clap_repl::reedline::{
    self, DefaultPrompt, DefaultPromptSegment, EditMode, Reedline, ReedlineEvent, Signal, Vi,
    default_vi_insert_keybindings, default_vi_normal_keybindings,
};
use colored::*;
use eyre::{Result, eyre};

pub fn read_line(prompt: &str) -> Result<String> {
    let mut rl = Reedline::create();
    match rl
        .read_line(&DefaultPrompt::new(
            DefaultPromptSegment::Basic(prompt.to_owned()),
            DefaultPromptSegment::Empty,
        ))
        .unwrap()
    {
        Signal::Success(x) => Ok(x),
        _ => Err(eyre!("Cancelled")),
    }
}

pub fn read<T>(prompt: &str) -> Result<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    let mut rl = Reedline::create();
    match rl
        .read_line(&DefaultPrompt::new(
            DefaultPromptSegment::Basic(prompt.to_owned()),
            DefaultPromptSegment::Empty,
        ))
        .unwrap()
    {
        Signal::Success(x) => {
            x.parse::<T>()
                // RUST_OPTION_RESULT_CONVERSIONS.md
                // https://gist.github.com/novafacing/6e087e5a62301a5b5c5a3fbd95263356
                // .map_err(|e| eyre!("Error parsing num: {:#?}", e))
                .map_err(|e| eyre!("Error parsing num: {:#?}", e))
        }
        _ => Err(eyre!("Cancelled")),
    }
}

pub fn read_password(prompt: &str) -> Result<String> {
    print!("{}", prompt.green());
    use termion::input::TermRead;
    let mut stdout = std::io::stdout().lock();
    let mut stdin = std::io::stdin().lock();
    let password = stdin.read_passwd(&mut stdout)?;
    match password {
        Some(password) => Ok(password),
        None => Err(eyre!("Cancelled")),
    }
}

pub fn confirm(prompt: &str, expected: &str) -> Result<bool> {
    let mut rl = Reedline::create();
    match rl
        .read_line(&DefaultPrompt::new(
            DefaultPromptSegment::Basic(prompt.to_owned()),
            DefaultPromptSegment::Empty,
        ))
        .unwrap()
    {
        Signal::Success(x) => match x.to_lowercase() == expected.to_string().to_lowercase() {
            true => Ok(true),
            false => Ok(false),
        },
        _ => Err(eyre!("Cancelled")),
    }
}

pub fn unwrap_or_prompt(value: &Option<String>, prompt: &str) -> Result<String> {
    match value {
        Some(value) => Ok(value.clone()),
        None => read_line(prompt),
    }
}

pub fn unwrap_or_prompt_for_password(password: &Option<String>, prompt: &str) -> Result<String> {
    let password: String = match password {
        Some(password) => password.clone(),
        None => read_password(prompt)?,
    };
    match password == read_password("Please confirm your password.\n")? {
        true => Ok(password),
        false => Err(eyre!("Passwords do not match!")),
    }
}

pub fn edit_mode_vi() -> Box<dyn EditMode> {
    let mut insert_keybinds = default_vi_insert_keybindings();
    insert_keybinds.add_binding(
        reedline::KeyModifiers::NONE,
        reedline::KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    Box::new(Vi::new(insert_keybinds, default_vi_normal_keybindings()))
}
