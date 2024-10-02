#!/bin/sh
ssh rigi-adm sudo -u kp -i tar zcf - $(find local -type f) | tar zxvf -