def hello():
    return "Hello, World!"

def add(a, b):
    return a + b

class Calculator:
    def __init__(self):
        self.result = 0
    
    def add(self, x):
        self.result += x
        return self
    
    def subtract(self, x):
        self.result -= x
        return self
    
    def get_result(self):
        return self.result

if __name__ == "__main__":
    print(hello())
    calc = Calculator()
    calc.add(5).subtract(3)
    print(f"Result: {calc.get_result()}")
