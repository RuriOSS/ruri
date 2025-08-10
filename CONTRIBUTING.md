# Commit Messages
We recommend, but do not strictly require, using a prefix for commit messages to indicate the type of change.     
The currently planned prefixes are:    
- feat: Add a new feature.    
- fix: Fix a bug.   
- sec: Security hardening.   
- build: Build system changes.   
- ci: Continuous integration changes.   
- doc: Documentation updates.   
- non: Non-core features (e.g., easter eggs, minor tweaks, non-critical changes).

# New Features
All new features must maintain backward compatibility.    
A new feature should have reasonably broad applicability rather than serving only a highly specific use case.    
When implementing a feature, avoid introducing new dependencies to the final binary whenever possible.     
