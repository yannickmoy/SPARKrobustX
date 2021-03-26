#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys

provers = ['z3', 'cvc4', 'altergo']
z3 = 0
cvc4 = 1
altergo = 2
num_provers = 3
prover_num = {'z3':0, 'cvc4':1, 'altergo':2}


def next_prover(prover):
    return provers[(prover_num[prover] + 1) % num_provers]


# Return prover pair in order, for faster runs
def prover_pair(prover):
    if prover_num[prover] == num_provers-1:
        return [next_prover(prover), prover]
    else:
        return [prover, next_prover(prover)]


versions = ['2018', '2019', '2020']
v2018 = 0
v2019 = 1
v2020 = 2
num_versions = 3
version_num = {'2018':0, '2019':1, '2020':2}

# dictionary from project name to
# dictionary from (version,prover) to (num_unproved,max_time_proved)
project_results = {}

verbose = False
num_procs = 0
root_results = '.'

def results_dir():
    return os.path.join(root_results, 'results')

def csv_dir():
    return os.path.join(root_results, 'csv')

root = {}
projects = []

is_msg = re.compile(r"([\w-]+\.ad.?):(\d+):(\d+):" +
                    r" (info|warning|low|medium|high): ([^(,[]*)(.*)?$")


def is_dependency_tag(tag):
    """Returns True if the given tag corresponds to a dependency flow
    message"""
    return tag in ("DEPENDS",
                   "GLOBAL")


def is_flow_initialization_tag(tag):
    """Returns True if the given tag corresponds to an initialization flow
    message"""
    return tag in ("INITIALIZED",
                   "INITIALIZES")


def is_aliasing_tag(tag):
    """Returns True if the given tag corresponds to an aliasing flow message"""
    return tag in ("ALIASING")


def is_termination_tag(tag):
    """Returns True if the given tag corresponds to a termination flow message"""
    return tag in ("TERMINATION")


def is_rte_tag(tag):
    """Returns True if the given tag corresponds to a RTE proof message"""
    return tag in ("DIVISION_CHECK",
                   "INDEX_CHECK",
                   "OVERFLOW_CHECK",
                   "RANGE_CHECK",
                   "LENGTH_CHECK",
                   "DISCRIMINANT_CHECK",
                   "TAG_CHECK",
                   "NULL_EXCLUSION",
                   "MEMORY_LEAK",
                   "DEREFERENCE_CHECK",
                   "UU_RESTRICTION")


def is_proof_initialization_tag(tag):
    """Returns True if the given tag corresponds to an initialization proof
    message"""
    return tag in ("INIT_BY_PROOF")


def is_ada_assertion_tag(tag):
    """Returns True if the given tag corresponds to an Ada assertion proof
    message"""
    return tag in ("PREDICATE_CHECK",
                   "INVARIANT_CHECK",
                   "PRECONDITION",
                   "PRECONDITION_MAIN",
                   "POSTCONDITION",
                   "ASSERT")


def is_spark_assertion_tag(tag):
    """Returns True if the given tag corresponds to an Ada assertion proof
    message"""
    return tag in ("DEFAULT_INITIAL_CONDITION",
                   "CONTRACT_CASE",
                   "DISJOINT_CONTRACT_CASE",
                   "COMPLETE_CONTRACT_CASE",
                   "LOOP_INVARIANT_INIT",
                   "LOOP_INVARIANT_PRESERV",
                   "LOOP_INVARIANT",
                   "LOOP_VARIANT",
                   "REFINED_POST",
                   "SUBPROGRAM_VARIANT")


def is_other_proof_tag(tag):
    """Returns True if the given tag corresponds to another proof message"""
    return tag in ("INITIAL_CONDITION",
                   "RAISE",
                   "TRIVIAL_PRE",
                   "WEAKER_PRE",
                   "STRONGER_POST",
                   "WEAKER_CLASSWIDE_PRE",
                   "STRONGER_CLASSWIDE_POST",
                   "WEAKER_PRE_ACCESS",
                   "STRONGER_POST_ACCESS",
                   "UNCHECKED_CONVERSION",
                   "UNCHECKED_CONVERSION_SIZE",
                   )


def is_flow_tag(tag):
    """Returns True if the given tag corresponds to a flow message"""
    return (is_dependency_tag(tag) or
            is_flow_initialization_tag(tag) or
            is_aliasing_tag(tag) or
            is_termination_tag(tag))


def is_info_only_tag(tag):
    """Returns True if the given tag corresponds to an info-only message"""
    return (tag == 'FUNCTION_CONTRACT')


def is_proof_tag(tag):
    """Returns True if the given tag corresponds to a proof message"""
    return (is_rte_tag(tag) or
            is_proof_initialization_tag(tag) or
            is_ada_assertion_tag(tag) or
            is_spark_assertion_tag(tag) or
            is_other_proof_tag(tag))


def get_tag(text):
    """Returns the tag for a given message text, or None if no tag is
    recognized."""

    # ??? simple string matching doesn't quite work when the message
    # contains several tags at once (e.g. 'global "xxx" is aliased')
    # or when the tag appears in an object name
    # (e.g. '"aliased" is missing from the Global contract')

    # flow analysis tags

    # When adding a tag in this section, you need also to update the
    # function is_flow_tag below.
    if 'aliased' in text:
        return 'ALIASING'
    elif 'dependency' in text or 'dependencies' in text:
        return 'DEPENDS'
    elif 'global' in text:
        return 'GLOBAL'
    elif 'initialized' in text or 'initialization of' in text:
        return 'INITIALIZED'
    elif 'initializes' in text:
        return 'INITIALIZES'
    elif 'terminate' in text:
        return 'TERMINATION'

    # info-only tags
    if 'function contract not available' in text:
        return 'FUNCTION_CONTRACT'

    # proof tags

    # When adding a tag in this section, you need also to update the
    # function is_proof_tag below.
    if 'division check' in text or 'divide by zero' in text:
        return 'DIVISION_CHECK'
    elif 'index check' in text:
        return 'INDEX_CHECK'
    elif 'overflow check' in text:
        return 'OVERFLOW_CHECK'
    elif 'predicate check' in text:
        return 'PREDICATE_CHECK'
    elif 'invariant check' in text:
        return 'INVARIANT_CHECK'
    elif 'range check' in text:
        return 'RANGE_CHECK'
    elif 'length check' in text:
        return 'LENGTH_CHECK'
    elif 'discriminant check' in text:
        return 'DISCRIMINANT_CHECK'
    elif 'tag check' in text:
        return 'TAG_CHECK'
    elif 'initialization check' in text:
        return 'INIT_BY_PROOF'
    elif 'null exclusion check' in text:
        return 'NULL_EXCLUSION'
    elif 'memory leak' in text:
        return 'MEMORY_LEAK'
    elif 'dereference check' in text:
        return 'DEREFERENCE_CHECK'
    elif 'operation on unchecked union type' in text:
        return 'UU_RESTRICTION'
    elif 'default initial condition' in text:
        return 'DEFAULT_INITIAL_CONDITION'
    elif 'initial condition' in text:
        return 'INITIAL_CONDITION'
    elif 'precondition' in text or 'nonreturning' in text:
        if 'of main program' in text:
            return 'PRECONDITION_MAIN'
        elif 'True' in text:
            return 'TRIVIAL_PRE'
        elif 'class-wide' in text and 'overridden' in text:
            return 'WEAKER_CLASSWIDE_PRE'
        elif 'class-wide' in text:
            return 'WEAKER_PRE'
        elif 'target' in text:
            return 'WEAKER_PRE_ACCESS'
        else:
            return 'PRECONDITION'
    elif 'postcondition' in text:
        if 'class-wide' in text and 'overridden' in text:
            return 'STRONGER_CLASSWIDE_POST'
        elif 'class-wide' in text:
            return 'STRONGER_POST'
        elif 'target' in text:
            return 'STRONGER_POST_ACCESS'
        else:
            return 'POSTCONDITION'
    elif 'refined post' in text:
        return 'REFINED_POST'
    elif 'contract case' in text:
        if 'disjoint' in text and 'contract cases' in text:
            return 'DISJOINT_CONTRACT_CASES'
        elif 'complete' in text and 'contract cases' in text:
            return 'COMPLETE_CONTRACT_CASES'
        else:
            return 'CONTRACT_CASE'
    elif 'loop invariant' in text:
        if 'initialization' in text or 'in first iteration' in text:
            return 'LOOP_INVARIANT_INIT'
        elif ('preservation' in text or
              'by an arbitrary iteration' in text or
              'after first iteration' in text):
            return 'LOOP_INVARIANT_PRESERV'
        else:
            return 'LOOP_INVARIANT'
    elif 'loop variant' in text:
        return 'LOOP_VARIANT'
    elif 'subprogram variant' in text:
        return 'SUBPROGRAM_VARIANT'
    elif 'assertion' in text:
        return 'ASSERT'
    elif 'raise statement' in text or 'exception' in text:
        return 'RAISE'
    elif 'bit representation' in text or 'unchecked conversion' in text:
        if 'size' in text:
            return 'UNCHECKED_CONVERSION_SIZE'
        else:
            return 'UNCHECKED_CONVERSION'

    # no tag recognized
    return None


def extract_one_line(results, version, prover, msg):
    m = re.match(is_msg, msg)
    if m:
        # extract groups from match
        filename = m.group(1)
        line = int(m.group(2))
        column = int(m.group(3))
        qual = m.group(4)
        text = m.group(5)
        rest = m.group(6)
        # extract information from groups
        unit = filename[:-4]
        tag = get_tag(text)
        proved = (qual == 'info')
        time = 0
        # Warnings are ignored
        if qual == 'warning':
            return
        if tag:
            # Checks from flow analysis or that are info-only are ignored
            if is_flow_tag(tag) or is_info_only_tag(tag):
                return
            # Only record the max time when a single prover is used
            if proved and len(prover) == 1:
                is_time = re.compile(prover[0] + r': \d+ VC in max (\d+).\d+ seconds', re.I)
                m = re.search(is_time, rest)
                if m:
                    time = int(m.group(1))
                else:
                    if verbose:
                        print('Missing time in message: ' + msg, end='')
            unit_results = results.setdefault(unit, dict())
            (num_unproved,max_time_proved) = unit_results.setdefault((version,prover), (0, 0))
            if not proved:
                num_unproved += 1
            if time > max_time_proved:
                max_time_proved = time
            unit_results[(version,prover)] = (num_unproved,max_time_proved)
            return
    # Reach here if the message or the tag were not recognized
    if verbose:
        print('Unrecognized message: ' + msg, end='')


def get_project_name(project):
    return os.path.basename(project['path'])[:-4]


def get_filename(project, version, prover):
    project_name = get_project_name(project)
    return os.path.join(results_dir(), project_name + '.' + version + '.' + '_'.join(prover))


def run_one_project_configuration(project, version, prover):
    # Pick the right version of GNATprove
    gnatprove = os.path.join('bin', 'gnatprove_' + version)
    project_path = os.path.join(root['path'], project['path'])

    # Start by removing all artefacts generated by a previous run
    clean_cmd = [gnatprove, '-P', project_path, '--clean']
    subprocess.run(clean_cmd, check=True)

    # Run GNATprove on the given project
    cmd = [gnatprove, '-P', project_path,
           '-j', str(num_procs),
           '--quiet',
           '--prover=' + ','.join(prover),
           '--timeout=60',
           '--steps=0',
           '--no-counterexample',
           '--report=statistics',
           '-u'] + project['files']
    resfile = get_filename(project, version, prover)
    with open(resfile, 'w') as outfile:
        header = {'project': project, 'version': version, 'prover': prover}
        print(json.dumps(header), file=outfile, flush=True)
        subprocess.run(cmd, stdout=outfile, encoding='utf-8', check=True)


def extract_one_file(results, resfile):
    with open(resfile, 'r') as infile:
        first = True
        for line in infile:
            # Extract (project, version, prover) from first line in file
            if first:
                first = False
                header = json.loads(line)
                project = header['project']
                version = header['version']
                prover = tuple(header['prover'])
            else:
                extract_one_line(results, version, prover, line)


def run_one_project(project):
    for version in versions:
        # Run single provers
        for prover in provers:
            run_one_project_configuration(project, version, [prover])
        # Run pairs of provers
        for prover in provers:
            run_one_project_configuration(project, version, prover_pair(prover))
        # Run all provers together
        run_one_project_configuration(project, version, provers)


def print_csv_line(outfile, index, line_name, line_results):
    print(line_name, end=', ', file=outfile)
    for version in versions:
        # Print results for single provers
        for prover in provers:
            print(line_results[(version,(prover,))][index], end=', ', file=outfile)
        # Print unproved results for combination of provers
        if index == 0:
            # Print results for pairs of provers
            for prover in provers:
                print(line_results[(version,tuple(prover_pair(prover)))][index], end=', ', file=outfile)
            # Print results for all provers together
            print(line_results[(version,tuple(provers))][index], end=', ', file=outfile)
    print('', file=outfile)


def print_csv_file(outfile, results, index):
    units = list(results.keys())
    units.sort()

    # Print header
    print('unit', end=', ', file=outfile)
    for version in versions:
        for prover in provers:
            print(version + '/' + prover, end=', ', file=outfile)
        # Print unproved results for combination of provers
        if index == 0:
            for prover in provers:
                print(version + '/' + prover + '+' + next_prover(prover), end=', ', file=outfile)
            print(version, end=', ', file=outfile)
    print('', file=outfile)

    # Print results for individual units
    for unit in units:
        print_csv_line(outfile, index, unit, results[unit])


# Print overall project results
def print_csv_total(outfile, totals, index):
    print_csv_line(outfile, index, 'total', totals)
    print('', file=outfile)
    # Print a separate table presenting the line for totals with provers vertically and versions horizontally
    print('', end=', ', file=outfile)
    for version in versions:
        print(version, end=', ', file=outfile)
    print('', file=outfile)
    for prover in provers:
        print(prover, end=', ', file=outfile)
        for version in versions:
            print(totals[(version,(prover,))][index], end=', ', file=outfile)
        print('', file=outfile)
    if index == 0:
        for prover in provers:
            print(prover + '+' + next_prover(prover), end=', ', file=outfile)
            for version in versions:
                print(totals[(version,tuple(prover_pair(prover)))][index], end=', ', file=outfile)
            print('', file=outfile)
        print('all', end=', ', file=outfile)
        for version in versions:
            print(totals[(version,tuple(provers))][index], end=', ', file=outfile)
        print('', file=outfile)


def print_csv_files(project_name, results, is_project):
    units = list(results.keys())
    units.sort()

    # dictionary from (version,prover) to (num_unproved,max_time_proved)
    totals = {}

    # Compute overall project results
    for version in versions:
        for prover in provers:
            totals[(version,(prover,))] = (0,0)
        for prover in provers:
            totals[(version,tuple(prover_pair(prover)))] = (0,0)
        totals[(version,tuple(provers))] = (0,0)

    for unit in units:
        for k,(num,time) in results[unit].items():
            (num_unproved,max_time_proved) = totals[k]
            totals[k] = (num_unproved + num, max(max_time_proved,time))

    # Update global project results
    if is_project:
        project_results[project_name] = totals

    # Produce CSV file for unproved results
    csvfile = os.path.join(csv_dir(), project_name + '_unproved.csv')
    with open(csvfile, 'w') as outfile:
        print_csv_file(outfile, results, index=0)
        print_csv_total(outfile, totals, index=0)

    # Produce CSV file for max proved time results
    csvfile = os.path.join(csv_dir(), project_name + '_max_time.csv')
    with open(csvfile, 'w') as outfile:
        print_csv_file(outfile, results, index=1)
        print_csv_total(outfile, totals, index=1)


def extract_one_project(project):
    project_name = get_project_name(project)

    # dictionary from unit to dictionary of results
    # of the form ((version,prover) -> (num_unproved,max_time_proved))
    results = {}

    # Extract information from all result files for this project
    for resfile in os.listdir(results_dir()):
        if resfile.startswith(project_name):
            extract_one_file(results, os.path.join(results_dir(), resfile))

    print_csv_files(project_name, results, is_project=True)


def aggregate_project_results():
    print_csv_files(root['name'], project_results, is_project=False)


if __name__ == '__main__':
    # Parse args
    parser = argparse.ArgumentParser()
    parser.add_argument('desc', help='the description of the projects to analyse')
    parser.add_argument('--verbose', action='store_true', help='print additional messages')
    parser.add_argument('--do', choices=['run', 'compare'], help='run the analyses or extract data from analyses')
    parser.add_argument('--output', help='specify to use a different output directory')
    parser.add_argument('--procs', type=int, default=0, help='max number of cores to use (default: all available)')
    args = parser.parse_args()

    verbose = args.verbose
    num_procs = args.procs

    if args.output is not None:
        root_results = args.output

    os.makedirs(results_dir(), exist_ok=True)
    os.makedirs(csv_dir(), exist_ok=True)

    # Run analysis by default or if --do=run was given
    do_run = args.do is None or args.do == 'run'
    # Run analysis by default or if --do=compare was given
    do_compare = args.do is None or args.do == 'compare'

    with open(args.desc, 'r') as descfile:
        desc = json.loads(descfile.read())
        root = desc['root']
        projects = desc['projects']

    for project in projects:
        if do_run:
            print('run project ' + get_project_name(project))
            run_one_project(project)
        if do_compare:
            print('extract project ' + get_project_name(project))
            extract_one_project(project)

    if do_compare and len(projects) > 1:
        print('aggregate project results')
        aggregate_project_results()
