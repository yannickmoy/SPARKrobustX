# SPARKrobustX
Supporting material for experimenting with the robustness of SPARK proofs

## Setup

### Installation of SPARK versions

You need first to download GNAT Community versions 2018, 2019 and 2020 from
[AdaCore website](https://www.adacore.com/download/more) for your platform.
Run the installers, choosing a suitable different location for each version.
Then create a symbolic link from ``bin/gnatprove_<version>`` to the
``gnatprove`` executable for each of the versions.

### Download the sources of projects

You can run the experiment with the projects that we used:

- [SPARK-by-Example](https://github.com/tofgarion/spark-by-example), a
  collection of small programs illustrating the practice of program proof with
  SPARK, developed by Christophe Garion et al. at the ISAE-SUPAERO engineering
  school.

- [SPARKNaCl](https://github.com/rod-chapman/SPARKNaCl), a rewrite of the
  cryptographic library TweetNaCl in SPARK by Rod Chapman

- [SPARK Red-Black
  Trees](http://toccata.lri.fr/gallery/spark_red_black_trees.en.html), an
  implementation of red-black trees in SPARK from Claire Dross, which was used
  as the basis for an article at NASA Formal Methods 2017

For each project on GitHub, we have tagged a specific version to use that can
be analyzed with all three versions of SPARK, with tag ``robustX``.  Also, we
have separately tagged a version without redundant assertions, with tag
``robustXnoassert``.  Use the following URLs to retrieve these versions:

- [SPARK-by-Example](https://github.com/yannickmoy/spark-by-example)

- [SPARKNaCl](https://github.com/yannickmoy/SPARKNaCl)

For SPARK Red-Black Trees, download the zip archive and use the following
project files:

- ``projects/sparkrbt.gpr`` for the run with assertions

- ``projects/sparkrbt_noassert.gpr`` together with file
  ``projects/noassert.adc`` for the run without assertions

Just copy these three files at the root of the ``spark_red_black_trees``
directory.

Then create a symbolic link from ``projects/<project>`` to the root of each
project.

### Prepare your own project

You can run also the experiment for your own SPARK project, provided it can be
analyzed by all three versions of SPARK.  Just add a suitable link as above,
plus a description of the project in directory ``desc`` (see our own
description files for the JSON format).

For the run without assertions, the easiest is to use a pragma configuration
file containing the line:

```
   pragma Assertion_Policy (Assert => Disable);
```

Make sure to use the attribute ``Switches`` (instead of the more recent
``Proof_Switches``) in package ``Prove`` in your project files for switches
that should be taken into account by GNATprove, as this is the only version
recognized by all three versions.

## Experiment

To run the experiment, execute the script ``run_and_compare.py`` on the
description of your project. You need a version of Python3 >= 3.5

GNATprove is run with all combination of provers among Alt-Ergo, CVC4 and Z3,
with all three versions of GNATprove found in GNAT Community 2018, 2019 and
2020. The following switches are passed on the command-line and take precedence
over switches found in the project file:

- ``--timeout=60`` - 60 seconds timeout for each proof attempt

- ``--steps=0`` - prover steps are not used (which makes the experiment not
  strictly deterministic, but using timeout is a better measure of effort
  across provers/versions)

- ``--no-counterexample`` - do not call provers to generate counterexamples

- ``--report=statistics`` - give detailed statistics in terms of maximum
  time/steps used for proving each check

Results of the GNATprove runs are stored under the ``results`` subdirectory, by
default under the current directory, or when ``--output`` switch is used under
that user-defined directory.

CSV files containing the data extracted from the above results are stored under
the ``csv`` subdirectory, by default under the current directory, or when
``--output`` switch is used under that user-defined directory.

Two types of CSV files are produced:

- files ``*_unproved.csv`` contain data about unproved checks

- files ``*_max_time.csv`` contain data about maximal time for proved checks

- files ``*_max_time_map.csv`` contain a mapping from maximal time for proved
  checks to the number of corresponding checks proved at this maximal time

## Results

Results for the three projects mentioned above are stored in:

- ``assertions_on`` for the results taking into account assertions in the code

- ``assertions_off`` for the results ignoring assertions in the code
