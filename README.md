## Build and Validation Instructions ##

### Stage 1 Solution

To build, run "make" in the project root directory.

```sh
make
```

An "apps" directory should have been created. The solutions are in this directory.

```sh
#From project root

cd ./apps
./stage_1_solution
```

To validate, make sure to start the solution executable before the python test. It will block until test.py is executed.

Copies of the tests are included in the project. You can run these tests from a separate terminal using the copies in the project if you wish, or use your own.
```sh
#From project root

cd ./stage-1
python3 test.py
```

### Stage 2 Solution ###

Stage 2 can be verified exactly the same way as stage 1. Both executables are built by running make.

```sh
#From project root

cd ./apps
./stage_2_solution
```

```sh
#From project root

cd ./stage-2
python3 test.py
```


### Checksum Verification ###

My checksum verification logic never seems to match on CTFS packets of length non-divisible by 4. This breaks 3.pdf and 4.pdf .
I've looked through my padding logic for any bugs but can't find any.

Nonetheless, checksum verification can be turned on with the following flag.

```sh
#From project root

cd ./apps
./stage_2_solution --checksum
```


### Python Prototypes ###

For the sake of personal enjoyment and demonstrating technical understanding, I completely refrained from using LLMs for research, code generation
or anything else. I made prototypes in Python to break down the problem.

If it's of interest, the directory python_solutions contains these prototypes.

```sh
#From project root

cd python_solutions
python3 stage_1.py
```
