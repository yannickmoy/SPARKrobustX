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

For each project, we have tagged a specific version to use that can be analyzed
with all three versions of SPARK, with tag ``robustX``.  Also, we have
separately tagged a version without redundant assertions, with tag
``robustXnoassert``.  Use the following URLs to retrieve these versions:

- [SPARK-by-Example](https://github.com/yannickmoy/spark-by-example)

- [SPARKNaCl](https://github.com/yannickmoy/SPARKNaCl)

Then create a symbolic link from ``projects/<project>`` to the root of each
project.

You can run also the experiment for your own SPARK project, provided it can be
analyzed by all three versions of SPARK.  Just add a suitable link as above,
plus a description of the project in directory ``desc`` (see our own
description files for the JSON format).

## Experiment

To run the experiment, execute the script ``run_and_compare.py`` on the
description of your project.

Results of the GNATprove runs are stored under the ``results`` subdirectory, by
default under the current directory, or when ``--output`` switch is used under
that user-defined directory.

CSV files containing the data extracted from the above results are stored under
the ``csv`` subdirectory, by default under the current directory, or when
``--output`` switch is used under that user-defined directory.

Two types of CSV files are produced:

- files ``*_unproved.csv`` contain data about unproved checks

- files ``*_max_time.csv`` contain data about maximal time for proved checks
