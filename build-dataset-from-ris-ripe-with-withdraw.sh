#!/bin/bash
#
# BGPSecX - To parse RIPE/RIS datasets
# By NETX-ULX Team, 2018

HOME=$(pwd)
MRT_DIR=$HOME/mrtparse
lastDir=$(basename $HOME)
rawDatasetPath=/home/rcosta/Regivaldo/BGPSecX/evaluation/datasets/raw/data.ris.ripe.net
parsedDatasetPath=/media/rcosta/RGC-Data-2TB/BGPSECx/datasets/data.ris.ripe.net/parsed

clear
#if [ "$lastDir" != "BGPSECx" ]; then
#   echo -e "You need to stay in the BGPSECx home directory cloned from github to execute this script.\n"
#   exit 
#fi

if [ $# -eq 0 ]; then
   clear
   echo -e "Sintax: script <rrc_begin> <rrc_end> <YYYYMM[DD][dd]>\n"
   exit
fi
 
if [ $# -eq 3 ]; then
   YEAR=$(echo $3 | /usr/bin/cut -c1-4)
   MONTH=$(echo $3 | /usr/bin/cut -c5-6)
   sizePar=$(echo -n $3 | wc -c)

   if [ $sizePar -gt 6 ]; then
      beginDay=$(echo $3 | /usr/bin/cut -c7-8)
   else
      beginDay="01"
      endDay="31"
   fi

   if [ $sizePar -gt 8 ]; then
      endDay=$(echo $3 | /usr/bin/cut -c9-10)
   else
      endDay=$beginDay
   fi

   for i in $(eval echo "{$1..$2}"); do
     if [ "$i" != "02" ] || [ "$i" != "08" ] || [ "$i" != "09" ] || [ "$i" != "17" ]; then   
        cd "$rawDatasetPath/rrc$i/$YEAR.$MONTH" 
        if [ ! -d "$DIRECTORY" ]; then
	   mkdir -p $parsedDatasetPath/rrc$i/$YEAR.$MONTH
        fi
        for thisDay in $(eval echo "{$beginDay..$endDay}"); do
          DAY=$YEAR$MONTH$thisDay
          for srcZipDataset in `ls -1 updates.$DAY.* | sort`; do  
            #/bin/gzip -df $srcZipDataset
            srcDataset=$(echo $rawDatasetPath/rrc$i/$YEAR.$MONTH/$srcZipDataset | /usr/bin/cut -d"." -f1-10)
            echo "Parsing the file: $srcDataset.gz"
	    dstParsedFile=$parsedDatasetPath/rrc$i/$YEAR.$MONTH/rrc$i.$(echo $srcZipDataset | /usr/bin/cut -d"." -f2-3).parsed
            echo "source=$srcDataset, dst=$dstParsedFile"
exit
            # AWK get only the 3, 6 and 7 collumn (it is announce/withdraw, NLRI and AS_PATH)
            #/usr/bin/python2.7 $MRT_DIR/examples/mrt2bgpdump.py $srcDataset | /bin/grep -E "A|W" | \
            #                   /usr/bin/awk -F'|' '{print $3" "$5" "$6" "$7}' >> $dstParsedFile
	    echo "+--------+"
          done
        done
     fi
   done
else
   echo -e "Wrong number of parameters. The sintax is like \"script_name <rrc_begin> <rrc_end> <YYYYMM[DD][dd]>\"\n"
fi

