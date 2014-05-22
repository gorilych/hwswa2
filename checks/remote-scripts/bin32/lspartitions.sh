#!/bin/sh
# this script should list partitions this way
#sda1|490.0G|/|ext4
#sda2|4.0G|-|swap
#sdb1|232.9G|/wd|ext4


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

mounts=$( { grep '^/dev/' /proc/mounts; grep '^/dev/' /proc/swaps | awk '{print $1, "-", "swap"}'; } \
          | while read p m fs rest; do 
            p=$(readlink -f $p)
            if [ "$p" = "/dev/root" ]; then
              # major:minor in decimal
              mm="$[ $(stat $p -c '0x%t') ]:$[ $(stat $p -c '0x%T') ]"
              p=$(find /sys/block/*/ -name dev | xargs grep -Fl $mm \
                  | sed -e 's%/dev$%%')
              p=/dev/${p##*/}
            fi
            echo $p $m $fs
          done)

for dev in $(find /sys/block/ -maxdepth 1 \( -name 'sd*' -o -name 'sr*' -o -name 'hd*' \
                                 -o -name 'vd*' \) | sed 's%^/sys/block/%%'); do
  blksize=$(cat /sys/block/$dev/queue/logical_block_size 2>/dev/null || echo 512)
  for partition in $(find /sys/block/$dev/ -name start \
                     | sed -e 's%^/sys/block/'$dev'/%%' -e 's%/start$%%' ); do
    size=$(cat /sys/block/$dev/$partition/size)
    size=$(human $(expr $size \* $blksize))
    mounted=$(echo "$mounts" | grep -q '^/dev/'$partition && echo 1 || echo 0)
    if [ "$mounted" = "0" ]; then
      mountpoint="-"
      filesystem="-"
    else
      mountpoint=$(echo "$mounts" | grep --max-count=1 '^/dev/'$partition | awk '{print $2}')
      filesystem=$(echo "$mounts" | grep --max-count=1 '^/dev/'$partition | awk '{print $3}')
      mounts=$(echo "$mounts" | grep --invert-match '^/dev/'$partition)
    fi
    echo "$partition|$size|$mountpoint|$filesystem"
  done
done

if [ ${#mounts} -gt 0 ]; then
  echo "$mounts" | while read p m fs; do
    size=$(df $m --human-readable --portability --print-type | tail -1 | awk '{print $3}')
    p=${p##*/}
    echo "$p|$size|$m|$fs"
  done
fi

