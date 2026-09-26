# Changelog

## Research preview

- Introduced direct static native-to-Python source emission.
- Added code-object to native-implementation joining with source-line validation.
- Added structured CFG, source-line and register/stack recovery paths.
- Added whole-binary source-tree emission, resume and partial refinement.
- Added conservative uncertainty handling and parseable-output audits.
- Improved recovery of iteration, unpacking, formatted strings, arithmetic slots and name-to-name assignments.
- Verified the current regression path on Python 3.10 open-source Nuitka and Python 3.11 commercial-layout samples from a Python 3.12 host.

This is a research preview. Compatibility outside the verified matrix remains best effort.
