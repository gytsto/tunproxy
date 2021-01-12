#! /bin/sh

# resuls file
output=static_analysis_results.txt

# list of standard rules
addons=""

# source directory relative to script path
source=../src

# show progress
progress=0

# analysis flags
flags="--enable=all"
flags="$flags --suppress=unusedFunction"
flags="$flags --force"
flags="$flags --std=c11"
flags="$flags --max-ctu-depth=32"
flags="$flags --platform=unix32"
flags="$flags --language=c"

script_dir=$(dirname "$(realpath $0)")

# path to custom rules
rules_path=$script_dir/rules.cfg

# dependencies
if ((progress == 0)); then
    flags="$flags --quiet"
else
    flags="$flags --report-progress"

fi

echo -n "running analysis..."
cppcheck --template="{severity}\t{id}\t{file}:{line}: {message}\n{callstack}" --template-location="{file}:{line}:\tnode: {info}\n{code}\n" $flags $script_dir/$source --output-file=$output $addons --library=$rules_path
echo "done"
echo "results: $(pwd)/$output"
echo ""
echo "Static analysis issue summary:"
echo "style       : $(less $output | grep style | wc -l)"
echo "warning     : $(less $output | grep warning | wc -l)"
echo "error       : $(less $output | grep error | wc -l)"
echo "performance : $(less $output | grep performance | wc -l)"
echo "portability : $(less $output | grep portability | wc -l)"
echo "total       : $(less $output | grep -E 'style|warning|error|performance|portability' | wc -l)"
