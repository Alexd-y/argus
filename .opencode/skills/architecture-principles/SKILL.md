---
name: architecture-principles
description: Software architecture principles and design patterns. Read by senior-reviewer before reviewing architecture, by planner when breaking down complex tasks, by worker when implementing new features or modules, and by reviewer when checking architectural consistency.
---

# Architecture Principles Skill

**Purpose**: Define architectural standards and design patterns for the project.

---

## Core Principles

### 1. SOLID Principles

#### Single Responsibility Principle (SRP)
- One class/module = one reason to change
- Separate concerns (data, logic, presentation)

```
// ✅ Good - Single responsibility
UserRepository:
  findById(id)  // DB logic only

UserService:
  validateUser(user)  // Business logic only

// ❌ Bad - Multiple responsibilities
User:
  save()      // DB logic
  validate()  // Business logic
  render()    // Presentation — three reasons to change
```

#### Open/Closed Principle (OCP)
- Open for extension, closed for modification
- Use interfaces, abstract classes, composition

#### Liskov Substitution Principle (LSP)
- Subtypes must be substitutable for base types
- Don't break parent class contracts

#### Interface Segregation Principle (ISP)
- Many specific interfaces > one general interface
- Clients shouldn't depend on unused methods

#### Dependency Inversion Principle (DIP)
- Depend on abstractions, not concretions
- High-level modules shouldn't depend on low-level modules

---

### 2. Separation of Concerns

#### Layered Architecture

```
┌─────────────────────────────┐
│   Presentation Layer        │  UI, Views, User Interface
├─────────────────────────────┤
│   Application Layer         │  Use Cases, Application Logic
├─────────────────────────────┤
│   Domain Layer              │  Business Logic, Entities
├─────────────────────────────┤
│   Data Layer                │  Data Access, Storage
├─────────────────────────────┤
│   Infrastructure Layer      │  External Services, I/O
└─────────────────────────────┘
```

**Rules:**
- Each layer only depends on layers below
- Business logic independent of infrastructure
- Easy to test each layer in isolation
- Upper layers depend on abstractions, not implementations

---

### 3. Design Patterns

#### Repository Pattern
Abstracts data access logic behind an interface so business logic doesn't depend on storage details.

```
// Contract — what operations are available
UserRepository (interface/protocol/trait):
  findById(id) → User or null
  save(user)
  delete(id)

// Concrete implementation — one per storage backend
DatabaseUserRepository implements UserRepository:
  constructor(db)
  findById(id) → db.query("SELECT ... WHERE id = ?", id)
  save(user)   → db.exec("INSERT OR UPDATE ...", user)

// Business logic only knows the interface, not the implementation
UserService:
  constructor(repo: UserRepository)  // injected
```

#### Service Pattern
Encapsulates business logic and orchestrates dependencies.

```
UserService:
  constructor(userRepo, notificationService)

  registerUser(data):
    1. validateRegistrationData(data)       // guard
    2. user = buildUserFromInput(data)      // domain logic
    3. userRepo.save(user)                  // persistence
    4. notificationService.sendWelcome(user) // side effect
    return user
```

#### Factory Pattern
Creates objects without hardcoding the concrete class at the call site.

```
PaymentProcessorFactory:
  create(type):
    if type == "stripe" → return StripeProcessor()
    if type == "paypal" → return PayPalProcessor()
    else → raise UnknownProcessorError(type)
```

#### Strategy Pattern
Encapsulates interchangeable algorithms behind a common interface.

```
// Contract
ValidationStrategy (interface):
  validate(value) → bool

// Implementations
EmailValidation implements ValidationStrategy:
  validate(email) → matchesEmailPattern(email)

PasswordValidation implements ValidationStrategy:
  validate(password) → length >= 8 AND hasUpperCase AND hasDigit

// Usage — caller doesn't know which strategy is used
Validator:
  constructor(strategy: ValidationStrategy)
  check(value) → strategy.validate(value)
```

---

### 4. Dependency Injection

**Benefits:**
- Loose coupling
- Easy testing (swap real deps for mocks/fakes)
- Flexible configuration

```
// ✅ Good - dependencies come in from outside
UserController:
  constructor(userService, logger)  // injected — easy to test/swap

// ❌ Bad - dependencies created internally
UserController:
  constructor():
    this.userService = new UserService()   // hardcoded — hard to test
    this.logger     = new ConsoleLogger()  // hardcoded — hard to swap
```

---

### 5. Error Handling

#### Centralized Error Handling

Use domain-specific error types instead of generic ones — callers can then handle each case explicitly.

```
// Domain error types (name them after what went wrong)
ValidationError(message, field?)   extends BaseError
NotFoundError(resource, id)        extends BaseError
UnauthorizedError(message)         extends BaseError

// Central handler dispatches by type
ErrorHandler:
  handle(error):
    if error is ValidationError  → respond 400, show field
    if error is NotFoundError    → respond 404
    if error is UnauthorizedError → respond 401
    else                         → respond 500, log details privately
    log(error.type, error.message)
```

---

### 6. Configuration Management

```
// ✅ Good - one place to read all config (env vars, files, flags)
config:
  environment    = env("APP_ENV", default="development")
  storage.type   = env("STORAGE_TYPE", default="local")
  logging.level  = env("LOG_LEVEL", default="info")
  features.maxRetries = env("MAX_RETRIES", default=3)

// ❌ Bad - config scattered across modules
// storage.go:    storageType = env("STORAGE_TYPE")
// logger.py:     logLevel    = env("LOG_LEVEL")
// retry.ts:      maxRetries  = env("MAX_RETRIES")
// → hard to find all config keys, easy to forget defaults
```

---

## Code Organization

### Feature-Based Structure
Best for large applications where features are relatively independent

```
src/
├── features/
│   ├── authentication/
│   │   ├── auth.service.ts
│   │   ├── auth.store.ts
│   │   ├── auth.types.ts
│   │   └── auth.utils.ts
│   ├── users/
│   │   ├── user.service.ts
│   │   ├── user.types.ts
│   │   └── user.utils.ts
│   └── notifications/
├── shared/
│   ├── components/
│   ├── utils/
│   └── types/
└── config/
```

**Advantages:**
- Features are self-contained
- Easy to find related code
- Can scale teams by feature
- Easy to remove/add features

### Layer-Based Structure
Best for smaller applications or when layers are more important than features

```
src/
├── services/
├── repositories/
├── models/
├── utils/
└── types/
```

**Advantages:**
- Clear technical boundaries
- Easier to enforce layer rules
- Good for smaller codebases
- Simple to understand

---

## Performance Principles

### 1. Data Access
- Index frequently accessed data
- Implement pagination for large datasets
- Use connection pooling for external resources
- Avoid N+1 queries (fetch related data efficiently)
- Lazy load data when appropriate

### 2. Caching
- Cache expensive computations
- Use appropriate cache invalidation strategies
- Consider memory vs speed tradeoffs
- Cache at the right layer (application, data, CDN)

### 3. Async Operations
- Use async/await for I/O operations
- Don't block the main thread
- Implement background jobs for heavy tasks
- Use queues/streams for decoupling
- Consider parallelization opportunities

### 4. Resource Management
- Clean up resources (connections, file handles, timers)
- Implement proper timeout mechanisms
- Use object pooling for expensive resources
- Monitor memory usage and prevent leaks

---

## Testing Strategy

### Test Pyramid

```
        /\
       /  \    E2E Tests (few)
      /----\
     /      \  Integration Tests (some)
    /--------\
   /          \ Unit Tests (many)
  /____________\
```

### What to Test:
- **Unit**: Business logic, utilities, pure functions, algorithms
- **Integration**: Component interactions, data flow, external services
- **E2E**: Critical user flows, main scenarios

---

## Anti-Patterns to Avoid

### ❌ God Object
One class that knows/does too much

### ❌ Spaghetti Code
Tangled, unstructured code with unclear flow

### ❌ Magic Numbers
Hardcoded values without explanation
```
// ❌ Bad
if user.age > 18 { ... }

// ✅ Good
MINIMUM_AGE = 18
if user.age > MINIMUM_AGE { ... }
```

### ❌ Circular Dependencies
Module A depends on B, B depends on A

### ❌ Premature Optimization
Optimizing before identifying actual bottlenecks

---

## Architecture Review Checklist

When reviewing architecture:

### Structure
- [ ] Clear separation of concerns
- [ ] Consistent folder structure
- [ ] Logical module boundaries

### Dependencies
- [ ] No circular dependencies
- [ ] Dependency injection used
- [ ] Abstractions over concretions

### Scalability
- [ ] Components/services are stateless where possible
- [ ] Data access is optimized (indexed, cached)
- [ ] Resource usage is efficient
- [ ] System can handle increased load

### Maintainability
- [ ] Code is self-documenting
- [ ] Consistent naming conventions
- [ ] Easy to add new features

### Testability
- [ ] Business logic isolated
- [ ] Dependencies can be mocked
- [ ] Test coverage adequate

---

## When to Refactor Architecture

Signs you need architectural changes:

1. **Adding features is increasingly difficult**
2. **Changes in one area break unrelated areas**
3. **Tests are hard to write or brittle**
4. **Code duplication everywhere**
5. **Performance issues at scale**

---

## References

- [Clean Architecture by Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Domain-Driven Design](https://martinfowler.com/bliki/DomainDrivenDesign.html)
- [Design Patterns: Elements of Reusable Object-Oriented Software](https://en.wikipedia.org/wiki/Design_Patterns)

---

**Note**: This skill should be consulted by agents when making architectural decisions or reviewing system design.
