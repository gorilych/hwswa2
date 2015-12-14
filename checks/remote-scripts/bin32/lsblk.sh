#!/bin/sh

# this script tries to imitate output of
# lsblk --noheadings --ascii --nodeps --output NAME,TYPE,RO,RM,ROTA,SIZE,MODEL
# BUT
# it also outputs VENDOR column
# columns are separated by pipe '|'

#from kernel sources:
#
#/*
#* DEVICE TYPES
#*/
#
##define TYPE_DISK 0x00
##define TYPE_TAPE 0x01
##define TYPE_PRINTER 0x02
##define TYPE_PROCESSOR 0x03 /* HP scanners use this */
##define TYPE_WORM 0x04 /* Treated as ROM by our system */
##define TYPE_ROM 0x05
##define TYPE_SCANNER 0x06
##define TYPE_MOD 0x07 /* Magneto-optical disk - 
#* - treated as TYPE_DISK */
##define TYPE_MEDIUM_CHANGER 0x08
##define TYPE_COMM 0x09 /* Communications device */
##define TYPE_RAID 0x0c
##define TYPE_ENCLOSURE 0x0d /* Enclosure Services Device */
##define TYPE_RBC     0x0e
##define TYPE_NO_LUN 0x7f

# this function converts file size number into human readable format
human () {
  local x=$1
  echo $x |\
  awk 'function human(x) {
         s="BKMGTEPYZ"
         while (x>=1024 && length(s)>1) 
               {x/=1024; s=substr(s,2)}
         s=substr(s,1,1)
         xf=(s=="B")?"%d":"%.1f"
         return sprintf( xf"%s\n", x, s)
      }
      {gsub(/^[0-9]+/, human($1)); print}'
}

BtoGB () {
  local x=$1
  echo $x | awk '{printf("%.3f",$1/1024/1024/1024)}' \
          | sed -e 's/\.0*$//' -e 's/\(\.[0-9]*[1-9]\)0*$/\1/'
}

for dev in $(find /sys/block/ -maxdepth 1 \( -name 'sd*' -o -name 'sr*' -o -name 'hd*' \
                                 -o -name 'vd*' -o -name 'xvd*' \) | sed 's%^/sys/block/%%'); do
  size=$(cat /sys/block/$dev/size)
  if [ "$size" = "0" ]; then
    continue
  fi
  blksize=$(cat /sys/block/$dev/queue/logical_block_size 2>/dev/null || echo 512)
  size=$(BtoGB $(expr $size \* $blksize))
  type=$(cat /sys/block/$dev/device/type 2>/dev/null || echo 0)
  if [ "$type" = "0" ]; then
    type="disk"
  elif [ "$type" = "5" ]; then
    type="rom"
  else
    continue # ignoring other devices
  fi
  readonly=$(cat /sys/block/$dev/ro 2>/dev/null || echo '-')
  removable=$(cat /sys/block/$dev/removable)
  rotational=$(cat /sys/block/$dev/queue/rotational 2>/dev/null || echo '-')
  model=$(cat /sys/block/$dev/device/model 2>/dev/null || echo '-')
  vendor=$(cat /sys/block/$dev/device/vendor 2>/dev/null || echo '-')
  echo "$dev|$type|$readonly|$removable|$rotational|$size|$vendor|$model"
  
done
