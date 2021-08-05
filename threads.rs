fn main() {
    println!("a");
    let jh1 = std::thread::spawn(|| println!("1"));
    println!("b {:?}", jh1.thread().id());
    let jh2 = std::thread::spawn(|| println!("2"));
    println!("c {:?}", jh2.thread().id());
    println!("3");
    jh1.join().unwrap();
    println!("d");
    jh2.join().unwrap();
    println!("e");
}
