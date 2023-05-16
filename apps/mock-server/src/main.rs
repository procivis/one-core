#![cfg_attr(feature = "strict", deny(warnings))]

fn main() {
    println!("Hello, world: {}!", one_core::add(1, 2));
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = one_core::add(2, 2);
        assert_eq!(result, 4);
    }
}
