function test_grep() {
  #echo grep \'$1\' $2
  ret=`grep -c "$1" $2`
  if [[ $ret == 1 ]];then
    echo 1
  else
    echo 0
  fi
}

list_input_files="list_nate_test list_readonly_test list_writeonly_test list_deleteonly_test"
read_input_files="read_nate_test1 read_nate_test2 read_nate_test3"
write_input_files="write_nate_test1 write_nate_test2"
error_list_input_files="error_nate_test1"
error_read_input_files="error_nate_test2 error_nate_test3"
test_output_file=testout.txt
score=0
score_possible=0
make_targets="sucms_list sucms_read sucms_write sucms_delete"


echo "Checking result of git pull command"
git pull

if [[ $? == 0 ]];then
  echo "Git pull success!"
  score=$((score + 1))
fi
score_possible=$((score_possible + 1))

for target in $make_targets;do
  echo "Checking make of each target"
  # Delete existing file first to make sure build actually works
  rm $target
  make $target
  if [[ $? == 0 ]];then
    echo "make $target success"
    score=$((score + 1))
  fi
  score_possible=$((score_possible + 1))

  if [[ -e $target ]];then
    echo "output file $target found"
    score=$((score + 1))
  fi
  score_possible=$((score_possible + 1))
done

#for f in $list_input_files;do
 # cat $f | ./sucms_list lincoln.cs.du.edu 8888 2>/dev/null 1>$test_output_file
  #while read line; do
   # ret=`grep -c "$line" $test_output_file`
    #if [[ $ret == 1 ]];then
     # score=$((score + 1))
    #else
     # echo "Missed line $line in output."
    #fi
    #score_possible=$((score_possible + 1))
  #done < $f\_EXPECTED.txt
#done

for f in $read_input_files;do
  outfile=`tail -n 1 $f`
  echo "outfile is $outfile"
  rm $outfile
  cat $f | ./sucms_read lincoln.cs.du.edu 8888 2>/dev/null 1>$test_output_file
  if [[ -e $outfile ]];then
    score=$((score + 1))
  fi
  score_possible=$((score_possible + 1))
  expected_md5=`cat $f.md5`
  actual_md5=`md5sum $outfile | awk '{ print $1 }'`
  echo "Expected md5 $expected_md5, actual $actual_md5"
  if [[ $expected_md5 == $actual_md5 ]];then
    score=$((score + 1))
  fi
  score_possible=$((score_possible + 1))
done

for f in $write_input_files;do
  infile=`tail -n 1 $f`
  echo "infile is $infile"
  cat $f | ./sucms_write lincoln.cs.du.edu 8888 2>/dev/null 1>$test_output_file
  # These checks can't be done without the server!
  #expected_md5=`cat $f.md5`
  #actual_md5=`md5sum $outfile | awk '{ print $1 }'`
  #echo "Expected md5 $expected_md5, actual $actual_md5"
  #if [[ $expected_md5 == $actual_md5 ]];then
  #  score=$((score + 1))
  #fi
  #score_possible=$((score_possible + 1))
done

for f in $error_list_input_files;do
  cat $f | ./sucms_list lincoln.cs.du.edu 8888 2>/dev/null 1>$test_output_file
  while read line; do
    ret=`grep -c "$line" $test_output_file`
    if [[ $ret == 1 ]];then
      score=$((score + 1))
    else
      echo "Missed line $line in output."
    fi
    score_possible=$((score_possible + 1))
  done < $f\_EXPECTED.txt
done

for f in $error_read_input_files;do
  cat $f | ./sucms_read lincoln.cs.du.edu 8888 2>/dev/null 1>$test_output_file
  while read line; do
    ret=`grep -c "$line" $test_output_file`
    if [[ $ret == 1 ]];then
      score=$((score + 1))
    else
      echo "Missed line $line in output."
    fi
    score_possible=$((score_possible + 1))
  done < $f\_EXPECTED.txt
done

echo "Total score $score out of $score_possible"


