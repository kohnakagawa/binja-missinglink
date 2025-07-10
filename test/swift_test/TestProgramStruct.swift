import Foundation

// Protocol for Protocol Witness Table testing
protocol Animal {
    func makeSound()
    func move()
    func getSpecies() -> String
}

// Struct using Protocol Witness Table
struct Dog: Animal {
    let breed: String
    
    init(breed: String = "Unknown") {
        self.breed = breed
    }
    
    func makeSound() {
        print("Dog: Woof!")
    }
    
    func move() {
        print("Dog: Running on four legs")
    }
    
    func getSpecies() -> String {
        return "Dog (\(breed))"
    }
}

// Struct using Protocol Witness Table
struct Cat: Animal {
    let color: String
    
    init(color: String = "Unknown") {
        self.color = color
    }
    
    func makeSound() {
        print("Cat: Meow!")
    }
    
    func move() {
        print("Cat: Walking gracefully")
    }
    
    func getSpecies() -> String {
        return "Cat (\(color))"
    }
}

// Function to demonstrate Protocol Witness Table indirect calls
@inline(never)
func testProtocolCall(_ animal: Animal) {
    // These calls will use Protocol Witness Table
    animal.makeSound()
    animal.move()
    print("Species: \(animal.getSpecies())")
}

// Main test function
func runTests() {
    print("Testing Protocol Witness Table indirect calls with structs:")
    
    // Create instances of our structs
    let dog = Dog(breed: "Shiba")
    let cat = Cat(color: "Orange")
    
    // Protocol Witness Table based calls
    print("\nTesting Dog:")
    testProtocolCall(dog)
    
    print("\nTesting Cat:")
    testProtocolCall(cat)
    
    // Demonstrate polymorphic behavior with structs
    let animals: [Animal] = [
        Dog(breed: "Shiba"),
        Cat(color: "Orange"),
        Dog(breed: "Golden Retriever"),
        Cat(color: "Black")
    ]
    
    print("\nTesting polymorphic behavior with structs:")
    for animal in animals {
        // This will use Protocol Witness Table
        animal.makeSound()
        print("Species: \(animal.getSpecies())")
    }
}

// Run the tests
runTests() 