build/rw_hook_cost 20 200000 2000   \
	| tee build/rw_hook_cost.txt
rw_hook_cost: libbpf v1.7, pinned to CPU 2, 20 rounds, 200000 reads per arm, 7 arms
coexist function=security_file_open opens=2000 session=2000 fentry=2000 ok
row round=-1 event=read arm=none n=20001 cpu_ns=2370323 wall_ns=2359524 hits=0 orphan=0 rmiss=0 lmiss=0
row round=-1 event=read arm=none2 n=20001 cpu_ns=2392498 wall_ns=2391451 hits=0 orphan=0 rmiss=0 lmiss=0
row round=-1 event=read arm=fentry n=20001 cpu_ns=4978507 wall_ns=4975675 hits=20001 orphan=0 rmiss=0 lmiss=0
row round=-1 event=read arm=fexit n=20001 cpu_ns=3521875 wall_ns=3530389 hits=20001 orphan=0 rmiss=0 lmiss=0
row round=-1 event=read arm=kpm n=20001 cpu_ns=5266334 wall_ns=5263730 hits=20001 orphan=0 rmiss=0 lmiss=0
row round=-1 event=read arm=pair n=20001 cpu_ns=13690151 wall_ns=13686948 hits=20001 orphan=0 rmiss=0 lmiss=0
row round=-1 event=read arm=session n=20001 cpu_ns=5560451 wall_ns=5557437 hits=20001 orphan=0 rmiss=0 lmiss=0
nullsys round=0 calls=1000000 total_ns=104184562
row round=0 event=read arm=none n=200000 cpu_ns=33004767 wall_ns=32997190 hits=0 orphan=0 rmiss=0 lmiss=0
row round=0 event=read arm=none2 n=200000 cpu_ns=26210131 wall_ns=26206880 hits=0 orphan=0 rmiss=0 lmiss=0
row round=0 event=read arm=fentry n=200000 cpu_ns=35326158 wall_ns=35129674 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=0 event=read arm=fexit n=200000 cpu_ns=36780801 wall_ns=36811072 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=0 event=read arm=kpm n=200000 cpu_ns=46498973 wall_ns=46558776 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=0 event=read arm=pair n=200000 cpu_ns=104518426 wall_ns=104519151 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=0 event=read arm=session n=200000 cpu_ns=52595890 wall_ns=52595054 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=1 calls=1000000 total_ns=86277984
row round=1 event=read arm=none2 n=200000 cpu_ns=24592759 wall_ns=24588771 hits=0 orphan=0 rmiss=0 lmiss=0
row round=1 event=read arm=fentry n=200000 cpu_ns=27749652 wall_ns=27753818 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=1 event=read arm=fexit n=200000 cpu_ns=29739883 wall_ns=30177484 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=1 event=read arm=kpm n=200000 cpu_ns=28496272 wall_ns=28495222 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=1 event=read arm=pair n=200000 cpu_ns=83231782 wall_ns=83232012 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=1 event=read arm=session n=200000 cpu_ns=52638012 wall_ns=52637520 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=1 event=read arm=none n=200000 cpu_ns=24363430 wall_ns=24372128 hits=0 orphan=0 rmiss=0 lmiss=0
nullsys round=2 calls=1000000 total_ns=84046493
row round=2 event=read arm=fentry n=200000 cpu_ns=26944832 wall_ns=26942212 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=2 event=read arm=fexit n=200000 cpu_ns=28794019 wall_ns=28841141 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=2 event=read arm=kpm n=200000 cpu_ns=28398720 wall_ns=28445214 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=2 event=read arm=pair n=200000 cpu_ns=84332737 wall_ns=84332227 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=2 event=read arm=session n=200000 cpu_ns=51591849 wall_ns=51591234 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=2 event=read arm=none n=200000 cpu_ns=23574764 wall_ns=23573399 hits=0 orphan=0 rmiss=0 lmiss=0
row round=2 event=read arm=none2 n=200000 cpu_ns=23918032 wall_ns=23917635 hits=0 orphan=0 rmiss=0 lmiss=0
nullsys round=3 calls=1000000 total_ns=84535967
row round=3 event=read arm=fexit n=200000 cpu_ns=29439338 wall_ns=29445063 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=3 event=read arm=kpm n=200000 cpu_ns=29268256 wall_ns=29309595 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=3 event=read arm=pair n=200000 cpu_ns=85212791 wall_ns=85210082 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=3 event=read arm=session n=200000 cpu_ns=64205379 wall_ns=64205069 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=3 event=read arm=none n=200000 cpu_ns=28095197 wall_ns=28102924 hits=0 orphan=0 rmiss=0 lmiss=0
row round=3 event=read arm=none2 n=200000 cpu_ns=27298697 wall_ns=27295300 hits=0 orphan=0 rmiss=0 lmiss=0
row round=3 event=read arm=fentry n=200000 cpu_ns=27451932 wall_ns=27498782 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=4 calls=1000000 total_ns=87421522
row round=4 event=read arm=kpm n=200000 cpu_ns=28363614 wall_ns=28362686 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=4 event=read arm=pair n=200000 cpu_ns=85952651 wall_ns=85952939 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=4 event=read arm=session n=200000 cpu_ns=50924059 wall_ns=50921972 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=4 event=read arm=none n=200000 cpu_ns=24937227 wall_ns=24942318 hits=0 orphan=0 rmiss=0 lmiss=0
row round=4 event=read arm=none2 n=200000 cpu_ns=24292795 wall_ns=24335679 hits=0 orphan=0 rmiss=0 lmiss=0
row round=4 event=read arm=fentry n=200000 cpu_ns=27005255 wall_ns=27058884 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=4 event=read arm=fexit n=200000 cpu_ns=30495974 wall_ns=30493100 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=5 calls=1000000 total_ns=103176523
row round=5 event=read arm=pair n=200000 cpu_ns=102777737 wall_ns=103373519 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=5 event=read arm=session n=200000 cpu_ns=53795722 wall_ns=53792594 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=5 event=read arm=none n=200000 cpu_ns=39584254 wall_ns=39585573 hits=0 orphan=0 rmiss=0 lmiss=0
row round=5 event=read arm=none2 n=200000 cpu_ns=43878729 wall_ns=43872309 hits=0 orphan=0 rmiss=0 lmiss=0
row round=5 event=read arm=fentry n=200000 cpu_ns=33510811 wall_ns=33510908 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=5 event=read arm=fexit n=200000 cpu_ns=33357664 wall_ns=33371837 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=5 event=read arm=kpm n=200000 cpu_ns=31557035 wall_ns=31569506 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=6 calls=1000000 total_ns=90351892
row round=6 event=read arm=session n=200000 cpu_ns=57013422 wall_ns=57009777 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=6 event=read arm=none n=200000 cpu_ns=25245452 wall_ns=25252586 hits=0 orphan=0 rmiss=0 lmiss=0
row round=6 event=read arm=none2 n=200000 cpu_ns=26733870 wall_ns=26774879 hits=0 orphan=0 rmiss=0 lmiss=0
row round=6 event=read arm=fentry n=200000 cpu_ns=26986229 wall_ns=27026699 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=6 event=read arm=fexit n=200000 cpu_ns=28788546 wall_ns=28785157 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=6 event=read arm=kpm n=200000 cpu_ns=29328388 wall_ns=29337864 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=6 event=read arm=pair n=200000 cpu_ns=85013888 wall_ns=85015048 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=7 calls=1000000 total_ns=87424702
row round=7 event=read arm=none n=200000 cpu_ns=24187116 wall_ns=24181014 hits=0 orphan=0 rmiss=0 lmiss=0
row round=7 event=read arm=none2 n=200000 cpu_ns=26242366 wall_ns=26238233 hits=0 orphan=0 rmiss=0 lmiss=0
row round=7 event=read arm=fentry n=200000 cpu_ns=27352122 wall_ns=27345921 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=7 event=read arm=fexit n=200000 cpu_ns=30403911 wall_ns=30405038 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=7 event=read arm=kpm n=200000 cpu_ns=30776944 wall_ns=30815840 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=7 event=read arm=pair n=200000 cpu_ns=91938302 wall_ns=91921147 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=7 event=read arm=session n=200000 cpu_ns=51185284 wall_ns=51182654 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=8 calls=1000000 total_ns=86034558
row round=8 event=read arm=none2 n=200000 cpu_ns=23854830 wall_ns=23851184 hits=0 orphan=0 rmiss=0 lmiss=0
row round=8 event=read arm=fentry n=200000 cpu_ns=28602427 wall_ns=29308749 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=8 event=read arm=fexit n=200000 cpu_ns=31070716 wall_ns=31110077 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=8 event=read arm=kpm n=200000 cpu_ns=32240924 wall_ns=32236125 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=8 event=read arm=pair n=200000 cpu_ns=81155068 wall_ns=81153169 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=8 event=read arm=session n=200000 cpu_ns=58006338 wall_ns=58001689 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=8 event=read arm=none n=200000 cpu_ns=28980256 wall_ns=29139099 hits=0 orphan=0 rmiss=0 lmiss=0
nullsys round=9 calls=1000000 total_ns=88921100
row round=9 event=read arm=fentry n=200000 cpu_ns=30226491 wall_ns=30231711 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=9 event=read arm=fexit n=200000 cpu_ns=32932404 wall_ns=32832268 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=9 event=read arm=kpm n=200000 cpu_ns=31996472 wall_ns=32002805 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=9 event=read arm=pair n=200000 cpu_ns=90584376 wall_ns=90581108 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=9 event=read arm=session n=200000 cpu_ns=52224474 wall_ns=52223604 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=9 event=read arm=none n=200000 cpu_ns=23852086 wall_ns=23858538 hits=0 orphan=0 rmiss=0 lmiss=0
row round=9 event=read arm=none2 n=200000 cpu_ns=24578943 wall_ns=24578835 hits=0 orphan=0 rmiss=0 lmiss=0
nullsys round=10 calls=1000000 total_ns=89887851
row round=10 event=read arm=fexit n=200000 cpu_ns=31725949 wall_ns=31728063 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=10 event=read arm=kpm n=200000 cpu_ns=30475617 wall_ns=30472640 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=10 event=read arm=pair n=200000 cpu_ns=85312494 wall_ns=85309774 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=10 event=read arm=session n=200000 cpu_ns=53815158 wall_ns=53810576 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=10 event=read arm=none n=200000 cpu_ns=24350495 wall_ns=24345900 hits=0 orphan=0 rmiss=0 lmiss=0
row round=10 event=read arm=none2 n=200000 cpu_ns=23793415 wall_ns=23789475 hits=0 orphan=0 rmiss=0 lmiss=0
row round=10 event=read arm=fentry n=200000 cpu_ns=27365364 wall_ns=27364071 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=11 calls=1000000 total_ns=85643777
row round=11 event=read arm=kpm n=200000 cpu_ns=27959376 wall_ns=27956379 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=11 event=read arm=pair n=200000 cpu_ns=87150221 wall_ns=87147828 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=11 event=read arm=session n=200000 cpu_ns=54995770 wall_ns=54994857 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=11 event=read arm=none n=200000 cpu_ns=25813461 wall_ns=25811870 hits=0 orphan=0 rmiss=0 lmiss=0
row round=11 event=read arm=none2 n=200000 cpu_ns=24077968 wall_ns=24085473 hits=0 orphan=0 rmiss=0 lmiss=0
row round=11 event=read arm=fentry n=200000 cpu_ns=28185938 wall_ns=28277715 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=11 event=read arm=fexit n=200000 cpu_ns=28959977 wall_ns=28966379 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=12 calls=1000000 total_ns=85636916
row round=12 event=read arm=pair n=200000 cpu_ns=87418139 wall_ns=87415801 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=12 event=read arm=session n=200000 cpu_ns=55529815 wall_ns=55527203 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=12 event=read arm=none n=200000 cpu_ns=24957934 wall_ns=24952575 hits=0 orphan=0 rmiss=0 lmiss=0
row round=12 event=read arm=none2 n=200000 cpu_ns=24037550 wall_ns=24033807 hits=0 orphan=0 rmiss=0 lmiss=0
row round=12 event=read arm=fentry n=200000 cpu_ns=28745068 wall_ns=28785787 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=12 event=read arm=fexit n=200000 cpu_ns=29787603 wall_ns=29782875 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=12 event=read arm=kpm n=200000 cpu_ns=31453838 wall_ns=31462469 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=13 calls=1000000 total_ns=88722581
row round=13 event=read arm=session n=200000 cpu_ns=58051566 wall_ns=58047685 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=13 event=read arm=none n=200000 cpu_ns=25635517 wall_ns=25688222 hits=0 orphan=0 rmiss=0 lmiss=0
row round=13 event=read arm=none2 n=200000 cpu_ns=25715583 wall_ns=25761583 hits=0 orphan=0 rmiss=0 lmiss=0
row round=13 event=read arm=fentry n=200000 cpu_ns=29512169 wall_ns=29519987 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=13 event=read arm=fexit n=200000 cpu_ns=31221817 wall_ns=31273734 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=13 event=read arm=kpm n=200000 cpu_ns=29748164 wall_ns=29746030 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=13 event=read arm=pair n=200000 cpu_ns=91979895 wall_ns=91978819 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=14 calls=1000000 total_ns=87562482
row round=14 event=read arm=none n=200000 cpu_ns=24011761 wall_ns=24002783 hits=0 orphan=0 rmiss=0 lmiss=0
row round=14 event=read arm=none2 n=200000 cpu_ns=23980512 wall_ns=23977501 hits=0 orphan=0 rmiss=0 lmiss=0
row round=14 event=read arm=fentry n=200000 cpu_ns=27983920 wall_ns=28019215 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=14 event=read arm=fexit n=200000 cpu_ns=29030892 wall_ns=29028069 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=14 event=read arm=kpm n=200000 cpu_ns=35384145 wall_ns=35396465 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=14 event=read arm=pair n=200000 cpu_ns=85100343 wall_ns=85111010 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=14 event=read arm=session n=200000 cpu_ns=56393123 wall_ns=56390001 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=15 calls=1000000 total_ns=91166782
row round=15 event=read arm=none2 n=200000 cpu_ns=23877786 wall_ns=23872089 hits=0 orphan=0 rmiss=0 lmiss=0
row round=15 event=read arm=fentry n=200000 cpu_ns=28228770 wall_ns=28232821 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=15 event=read arm=fexit n=200000 cpu_ns=31854054 wall_ns=31900332 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=15 event=read arm=kpm n=200000 cpu_ns=29885115 wall_ns=29901526 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=15 event=read arm=pair n=200000 cpu_ns=106510936 wall_ns=106507396 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=15 event=read arm=session n=200000 cpu_ns=52128238 wall_ns=52124757 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=15 event=read arm=none n=200000 cpu_ns=28099775 wall_ns=28106005 hits=0 orphan=0 rmiss=0 lmiss=0
nullsys round=16 calls=1000000 total_ns=90986109
row round=16 event=read arm=fentry n=200000 cpu_ns=27051884 wall_ns=27061148 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=16 event=read arm=fexit n=200000 cpu_ns=28241388 wall_ns=28251946 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=16 event=read arm=kpm n=200000 cpu_ns=28711220 wall_ns=28716950 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=16 event=read arm=pair n=200000 cpu_ns=100314354 wall_ns=100312981 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=16 event=read arm=session n=200000 cpu_ns=54077045 wall_ns=54075169 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=16 event=read arm=none n=200000 cpu_ns=24530857 wall_ns=24539149 hits=0 orphan=0 rmiss=0 lmiss=0
row round=16 event=read arm=none2 n=200000 cpu_ns=23803441 wall_ns=23803148 hits=0 orphan=0 rmiss=0 lmiss=0
nullsys round=17 calls=1000000 total_ns=92829385
row round=17 event=read arm=fexit n=200000 cpu_ns=29519327 wall_ns=29514722 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=17 event=read arm=kpm n=200000 cpu_ns=29091499 wall_ns=29088360 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=17 event=read arm=pair n=200000 cpu_ns=88660966 wall_ns=88669230 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=17 event=read arm=session n=200000 cpu_ns=51918076 wall_ns=51914825 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=17 event=read arm=none n=200000 cpu_ns=25080769 wall_ns=25087688 hits=0 orphan=0 rmiss=0 lmiss=0
row round=17 event=read arm=none2 n=200000 cpu_ns=24266994 wall_ns=24266556 hits=0 orphan=0 rmiss=0 lmiss=0
row round=17 event=read arm=fentry n=200000 cpu_ns=27938650 wall_ns=27946635 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=18 calls=1000000 total_ns=86506890
row round=18 event=read arm=kpm n=200000 cpu_ns=30676978 wall_ns=30680893 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=18 event=read arm=pair n=200000 cpu_ns=91734837 wall_ns=91733430 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=18 event=read arm=session n=200000 cpu_ns=53575696 wall_ns=53574677 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=18 event=read arm=none n=200000 cpu_ns=26450643 wall_ns=26457360 hits=0 orphan=0 rmiss=0 lmiss=0
row round=18 event=read arm=none2 n=200000 cpu_ns=24448118 wall_ns=24490018 hits=0 orphan=0 rmiss=0 lmiss=0
row round=18 event=read arm=fentry n=200000 cpu_ns=37767385 wall_ns=37820365 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=18 event=read arm=fexit n=200000 cpu_ns=29898966 wall_ns=29902053 hits=200000 orphan=0 rmiss=0 lmiss=0
nullsys round=19 calls=1000000 total_ns=85174837
row round=19 event=read arm=pair n=200000 cpu_ns=85116368 wall_ns=85116223 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=19 event=read arm=session n=200000 cpu_ns=52156242 wall_ns=52155315 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=19 event=read arm=none n=200000 cpu_ns=27841097 wall_ns=27846693 hits=0 orphan=0 rmiss=0 lmiss=0
row round=19 event=read arm=none2 n=200000 cpu_ns=28416921 wall_ns=28423634 hits=0 orphan=0 rmiss=0 lmiss=0
row round=19 event=read arm=fentry n=200000 cpu_ns=31718728 wall_ns=31714755 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=19 event=read arm=fexit n=200000 cpu_ns=30117797 wall_ns=30121173 hits=200000 orphan=0 rmiss=0 lmiss=0
row round=19 event=read arm=kpm n=200000 cpu_ns=29766094 wall_ns=29764649 hits=200000 orphan=0 rmiss=0 lmiss=0
rw_hook_cost: ok
python3 bench/rw_hook_cost/summarize.py build/rw_hook_cost.txt
# rw_hook_cost: hook types on vfs_read (ADR-0015 decision 1a, N5)

Null syscall (getppid), median over rounds: 87.5 ns.

## cpu time per read (primary; 20 rounds)

| arm | median | 95 % interval |
|---|---|---|
| none | 125.8 ns | 121.8 ns to 139.2 ns |
| none2 | 121.9 ns | 119.9 ns to 131.1 ns |
| fentry | 140.4 ns | 136.8 ns to 147.6 ns |
| fexit | 150.0 ns | 147.2 ns to 156.1 ns |
| kpm | 149.1 ns | 145.5 ns to 157.3 ns |
| pair | 436.4 ns | 425.6 ns to 459.7 ns |
| session | 268.4 ns | 260.8 ns to 277.6 ns |

- **fentry against none:** overhead +11.04 %, 95 % interval +6.06 % to +14.13 %, Wilcoxon p = 0.00121
  - added per read 14.2 ns (95 % interval 7.9 ns to 17.8 ns), 0.16 null syscalls; ratio of medians 1.1161; effect p = 0.00121
- **fexit against none:** overhead +16.70 %, 95 % interval +12.56 % to +21.35 %, Wilcoxon p = 0.000105
  - added per read 21.5 ns (95 % interval 16.8 ns to 26.1 ns), 0.25 null syscalls; ratio of medians 1.1926; effect p = 0.000105
- **kpm against none:** overhead +16.51 %, 95 % interval +11.45 % to +23.52 %, Wilcoxon p = 0.000261
  - added per read 20.8 ns (95 % interval 15.0 ns to 30.6 ns), 0.24 null syscalls; ratio of medians 1.1853; effect p = 0.000261
- **pair against none:** overhead +245.83 %, 95 % interval +225.94 % to +258.08 %, Wilcoxon p = 1.91e-06
  - added per read 315.1 ns (95 % interval 302.8 ns to 331.7 ns), 3.60 null syscalls; ratio of medians 3.4687; effect p = 1.91e-06
- **session against none:** overhead +111.47 %, 95 % interval +99.11 % to +119.35 %, Wilcoxon p = 1.91e-06
  - added per read 141.0 ns (95 % interval 130.8 ns to 149.0 ns), 1.61 null syscalls; ratio of medians 2.1335; effect p = 1.91e-06
- **session against pair:** overhead -39.29 %, 95 % interval -42.57 % to -36.70 %, Wilcoxon p = 1.91e-06
  - added per read -174.8 ns (95 % interval -201.6 ns to -157.6 ns), -2.00 null syscalls; ratio of medians 0.6151; effect p = 1.91e-06
- **session against fexit:** overhead +77.56 %, 95 % interval +70.05 % to +85.93 %, Wilcoxon p = 1.91e-06
  - added per read 118.2 ns (95 % interval 108.0 ns to 126.5 ns), 1.35 null syscalls; ratio of medians 1.7890; effect p = 1.91e-06
- **session against kpm:** overhead +78.09 %, 95 % interval +71.58 % to +85.26 %, Wilcoxon p = 1.91e-06
  - added per read 116.8 ns (95 % interval 111.2 ns to 125.9 ns), 1.34 null syscalls; ratio of medians 1.8000; effect p = 1.91e-06

## wall time per read (secondary; 20 rounds)

| arm | median | 95 % interval |
|---|---|---|
| none | 125.9 ns | 121.9 ns to 139.2 ns |
| none2 | 122.1 ns | 119.9 ns to 131.0 ns |
| fentry | 140.6 ns | 136.8 ns to 147.6 ns |
| fexit | 150.7 ns | 147.2 ns to 156.4 ns |
| kpm | 149.2 ns | 145.4 ns to 157.3 ns |
| pair | 436.4 ns | 425.6 ns to 459.6 ns |
| session | 268.4 ns | 260.8 ns to 277.6 ns |

- **fentry against none:** overhead +11.13 %, 95 % interval +6.46 % to +14.22 %, Wilcoxon p = 0.000851
  - added per read 14.1 ns (95 % interval 8.2 ns to 18.0 ns), 0.16 null syscalls; ratio of medians 1.1174; effect p = 0.000851
- **fexit against none:** overhead +16.84 %, 95 % interval +12.57 % to +21.34 %, Wilcoxon p = 0.000105
  - added per read 21.7 ns (95 % interval 16.8 ns to 26.4 ns), 0.25 null syscalls; ratio of medians 1.1978; effect p = 0.000105
- **kpm against none:** overhead +16.46 %, 95 % interval +11.44 % to +23.50 %, Wilcoxon p = 0.000261
  - added per read 20.8 ns (95 % interval 15.0 ns to 30.5 ns), 0.24 null syscalls; ratio of medians 1.1853; effect p = 0.000261
- **pair against none:** overhead +245.78 %, 95 % interval +225.54 % to +257.90 %, Wilcoxon p = 1.91e-06
  - added per read 315.1 ns (95 % interval 302.7 ns to 331.6 ns), 3.60 null syscalls; ratio of medians 3.4677; effect p = 1.91e-06
- **session against none:** overhead +111.40 %, 95 % interval +99.05 % to +119.32 %, Wilcoxon p = 1.91e-06
  - added per read 141.0 ns (95 % interval 130.8 ns to 148.8 ns), 1.61 null syscalls; ratio of medians 2.1328; effect p = 1.91e-06
- **session against pair:** overhead -39.29 %, 95 % interval -42.71 % to -36.70 %, Wilcoxon p = 1.91e-06
  - added per read -174.9 ns (95 % interval -202.7 ns to -157.6 ns), -2.00 null syscalls; ratio of medians 0.6151; effect p = 1.91e-06
- **session against fexit:** overhead +77.40 %, 95 % interval +69.94 % to +85.61 %, Wilcoxon p = 1.91e-06
  - added per read 118.0 ns (95 % interval 107.7 ns to 126.4 ns), 1.35 null syscalls; ratio of medians 1.7806; effect p = 1.91e-06
- **session against kpm:** overhead +78.03 %, 95 % interval +71.55 % to +85.19 %, Wilcoxon p = 1.91e-06
  - added per read 116.8 ns (95 % interval 111.1 ns to 125.9 ns), 1.34 null syscalls; ratio of medians 1.7995; effect p = 1.91e-06

## Kernel skip counters, all rounds

| arm | recursion_misses | kprobe_multi.missed |
|---|---|---|
| none | 0 | 0 |
| none2 | 0 | 0 |
| fentry | 0 | 0 |
| fexit | 0 | 0 |
| kpm | 0 | 0 |
| pair | 0 | 0 |
| session | 0 | 0 |

## kprobe.session and fentry on one function

- security_file_open: 2000 opens, session 2000, fentry 2000: ok

