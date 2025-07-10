import Foundation

// Protocol for Protocol Witness Table testing
protocol Animal {
    func makeSound()
    func move()
}

// Class using vtable
class Dog {
    func makeSound() {
        print("Dog: Woof!")
    }
    
    func move() {
        print("Dog: Running on four legs")
    }
    
    // Add a virtual method that can be overridden
    func getBreed() -> String {
        return "Unknown Breed"
    }
}

// PoodleDog class inheriting from Dog
class PoodleDog: Dog {
    private let curliness: Int
    
    init(curliness: Int = 5) {
        self.curliness = curliness
        super.init()
    }
    
    // Override methods from Dog class
    override func makeSound() {
        print("PoodleDog: Yip! Yip!")
    }
    
    override func move() {
        print("PoodleDog: Proudly trotting")
    }
    
    override func getBreed() -> String {
        return "Poodle"
    }
    
    // Poodle-specific method
    func getCurliness() -> Int {
        return curliness
    }
}

// Class using vtable
class Cat {
    func makeSound() {
        print("Cat: Meow!")
    }
    
    func move() {
        print("Cat: Walking gracefully")
    }
}

// Protocol conformance for Protocol Witness Table testing
extension Dog: Animal {}
extension Cat: Animal {}

// Function to demonstrate Protocol Witness Table indirect calls
@inline(never)
func testProtocolCall(_ animal: Animal) {
    // These calls will use Protocol Witness Table
    animal.makeSound()
    animal.move()
}

// Function to demonstrate vtable indirect calls
@inline(never)
func testVTableCall(_ animal: Dog) {
    // These calls will use vtable
    animal.makeSound()
    animal.move()
    print("Breed: \(animal.getBreed())")
}

// Main test function
func runTests() {
    print("Testing Protocol Witness Table indirect calls:")
    let dog: Animal = Dog()
    let cat: Animal = Cat()
    
    // Protocol Witness Table based calls
    testProtocolCall(dog)
    testProtocolCall(cat)
    
    print("\nTesting vtable indirect calls:")
    // Test vtable calls with Dog
    let regularDog = Dog()
    testVTableCall(regularDog)
    
    // Test vtable calls with PoodleDog
    let poodle = PoodleDog(curliness: 7)
    testVTableCall(poodle)  // This will use vtable to call PoodleDog's implementation
    
    // Demonstrate polymorphic behavior
    let animals: [Animal] = [Dog(), Cat(), PoodleDog()]  // Add PoodleDog to the array
    print("\nTesting polymorphic behavior:")
    for animal in animals {
        // This will use Protocol Witness Table
        animal.makeSound()
    }
}

// Run the tests
runTests() 