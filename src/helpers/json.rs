use eyre::Result;
use std::path::PathBuf;

pub fn update<T>(json_path: &PathBuf, keyval: Vec<(&str, T)>) -> Result<()>
where
    T: std::fmt::Display + serde::Serialize,
{
    let file = std::fs::File::open(&json_path)?;
    let mut keystore = serde_json::from_reader::<_, serde_json::Value>(&file)?;
    if let Some(obj) = keystore.as_object_mut() {
        for tuple in keyval.iter() {
            obj.insert(tuple.0.to_string(), serde_json::json!(tuple.1));
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            // Add truncate or shorter names will malform our store
            // https://ddanilov.me/how-to-overwrite-a-file-in-rust
            .truncate(true)
            .open(&json_path)?;
        serde_json::to_writer(&mut file, &obj)?;
    }
    Ok(())
}
