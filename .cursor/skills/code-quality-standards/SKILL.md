---
name: code-quality-standards
description: Code quality standards and refactoring guidelines. Read by refactor agent before refactoring, by reviewer for quality checks, by worker when writing code, and by debugger when fixing issues.
---

# Code Quality Standards Skill

**Purpose**: Define code quality standards, best practices, and refactoring patterns.

---

## Code Quality Principles

### 1. Readability

Code is read 10x more than written. Optimize for reading.

#### Clear Naming
```
// ✅ Good - Self-explanatory
function calculateMonthlyPayment(principal, rate, months)
  return (principal * rate) / (1 - pow(1 + rate, -months))

// ❌ Bad - Unclear
function calc(p, r, m)
  return (p * r) / (1 - pow(1 + r, -m))
```

#### Small Functions
- Max 20-30 lines per function
- One level of abstraction per function
- Do one thing well

```
// ✅ Good - Small, focused
function validateEmail(email)
  return isValidEmailFormat(email)

function validatePassword(password)
  return length(password) >= 8 AND hasUpperCase(password) AND hasDigit(password)

function validateUser(user)
  return validateEmail(user.email) AND validatePassword(user.password)

// ❌ Bad - Too long, does multiple things
function validateUser(user)
  // 50+ lines of validation logic
```

---

### 2. DRY (Don't Repeat Yourself)

#### Extract Common Logic
```
// ❌ Bad - Duplication
function getActiveUsers()
  return filter(users, u => u.status == 'active' AND u.deletedAt == null)

function getActivePosts()
  return filter(posts, p => p.status == 'active' AND p.deletedAt == null)

// ✅ Good - Extracted common logic
function isActive(item)
  return item.status == 'active' AND item.deletedAt == null

function getActiveUsers()
  return filter(users, isActive)

function getActivePosts()
  return filter(posts, isActive)
```

---

### 3. KISS (Keep It Simple, Stupid)

#### Prefer Simple Solutions
```
// ✅ Good - Simple and clear
function isEven(n)
  return n % 2 == 0

// ❌ Bad - Over-engineered
function isEven(n)
  return (n & 1 == 0) ? true : false
```

---

### 4. YAGNI (You Aren't Gonna Need It)

Don't add functionality until it's needed.

```
// ❌ Bad - Unused complexity
User:
  name
  email
  phone     // Maybe we'll need it later?
  fax       // Just in case?
  twitter   // Why not?

// ✅ Good - Only what's needed now
User:
  name
  email
```

---

## Code Smells & Refactoring

### 1. Long Method
**Smell**: Function > 30 lines

**Refactor**: Extract smaller functions

### 2. Large Class
**Smell**: Class with too many responsibilities

**Refactor**: Split into smaller classes (SRP)

### 3. Long Parameter List
**Smell**: Function with 4+ parameters

**Refactor**: Use object parameter or builder pattern

```
// ❌ Bad
function createUser(name, email, age, address, phone)

// ✅ Good
CreateUserParams:
  name
  email
  age
  address
  phone

function createUser(params: CreateUserParams)
```

### 4. Duplicated Code
**Smell**: Same code in multiple places

**Refactor**: Extract to shared function/class

### 5. Primitive Obsession
**Smell**: Using primitives instead of small objects

**Refactor**: Create value objects

```
// ❌ Bad
function sendEmail(email: String)
  // No validation, easy to pass invalid email

// ✅ Good
Email:
  value: String
  
  constructor(emailString)
    if NOT isValidEmail(emailString)
      throw Error('Invalid email')
    this.value = emailString
  
  function isValidEmail(email)
    return matchesEmailPattern(email)
  
  function toString()
    return this.value

function sendEmail(email: Email)
  // Email is guaranteed to be valid
```

### 6. Feature Envy
**Smell**: Method uses data from another class more than its own

**Refactor**: Move method to the other class

### 7. Dead Code
**Smell**: Unused functions, variables, imports

**Refactor**: Remove it

---

## Best Practices

### 1. Error Handling

```
// ✅ Good - Specific error types
ValidationError extends Error:
  constructor(message)
    super(message)
    this.name = 'ValidationError'

try:
  validateUser(user)
catch error:
  if error is ValidationError:
    // Handle validation errors
  else:
    // Handle other errors

// ❌ Bad - Generic errors
try:
  validateUser(user)
catch error:
  log('Error:', error)
```

### 2. Null Safety

```
// ✅ Good - Explicit null handling
function getUser(id): User or null
  return find(users, u => u.id == id) or null

user = getUser('123')
if user is not null:
  print(user.name)

// ❌ Bad - Implicit nulls
function getUser(id): User
  return find(users, u => u.id == id)

user = getUser('123')
print(user.name)  // Potential crash if null
```

### 3. Immutability

```
// ✅ Good - Immutable (create new object)
updatedUser = copyWithChanges(user, { name: 'New Name' })

// ❌ Bad - Mutation (modify existing object)
user.name = 'New Name'
```

### 4. Pure Functions

```
// ✅ Good - Pure function
function add(a, b)
  return a + b

// ❌ Bad - Side effects
total = 0
function add(a, b)
  total = total + a + b  // Modifies external state
  return total
```

---

## Refactoring Checklist

Before refactoring:
- [ ] Tests are in place (to verify behavior doesn't change)
- [ ] Code smell identified
- [ ] Refactoring technique chosen

During refactoring:
- [ ] Make small, incremental changes
- [ ] Run tests after each change
- [ ] Commit after each successful refactoring

After refactoring:
- [ ] All tests still pass
- [ ] Code is more readable
- [ ] Complexity reduced
- [ ] No new bugs introduced

---

## Complexity Metrics

### Cyclomatic Complexity
- **1-5**: Simple, low risk
- **6-10**: Moderate complexity
- **11-20**: High complexity, consider refactoring
- **21+**: Very high risk, must refactor

```
// High complexity (many branches)
function processOrder(order)
  if order.status == 'pending':
    if order.total > 1000:
      if order.customer.vip:
        // ...
      else:
        // ...
    else:
      // ...
  else if order.status == 'shipped':
    // ...
  // ... more branches

// Better - Use polymorphism or strategy pattern
```

---

## Code Review Checklist

When reviewing code for quality:

### Readability
- [ ] Clear variable/function names
- [ ] Functions are small and focused
- [ ] Comments explain "why", not "what"
- [ ] Consistent formatting

### Maintainability
- [ ] No code duplication
- [ ] Single Responsibility Principle
- [ ] Low coupling, high cohesion
- [ ] Easy to extend

### Correctness
- [ ] Edge cases handled
- [ ] Error handling implemented
- [ ] Input validation present
- [ ] Tests cover main scenarios

### Performance
- [ ] No obvious bottlenecks
- [ ] Efficient algorithms used
- [ ] Database queries optimized
- [ ] Unnecessary work avoided

---

## Common Refactoring Patterns

### Extract Method
Split long method into smaller ones

### Rename Variable/Method
Use descriptive names

### Replace Magic Number with Constant
```
// Before: if (age > 18)
LEGAL_AGE = 18
if (age > LEGAL_AGE)
```

### Introduce Parameter Object
Replace long parameter lists with objects

### Replace Conditional with Polymorphism
Replace if/switch with class hierarchy

---

## References

- [Clean Code by Robert C. Martin](https://www.oreilly.com/library/view/clean-code-a/9780136083238/)
- [Refactoring by Martin Fowler](https://refactoring.com/)
- [Code Smells Catalog](https://refactoring.guru/refactoring/smells)

---

**Note**: These standards should be applied consistently across the codebase. Agents should reference this skill when writing, reviewing, or refactoring code.
