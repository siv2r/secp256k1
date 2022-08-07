bench_output.txt: bench.sh
	SECP256K1_BENCH_ITERS=50000 ./bench.sh bench_output.txt

batch.dat: bench_output.txt
	cat bench_output.txt | grep -v "schnorrsig_batch_verify_1 " | awk '{ gsub(/ /,""); print }' | awk -F, 'match($$0, /schnorrsig_batch_verify_([0-9]+)/, arr) {print arr[1] " " $$3}' > batch.dat

single.dat: bench_output.txt
	cat bench_output.txt | awk '{ gsub(/ /,""); print }' | awk -F, 'match($$0, /schnorrsig_verify/) {print $$3}' > single.dat

speedup-batch.png: batch.dat single.dat plot.gp
	gnuplot plot.gp

clean:
	rm *.log *.txt *.dat *.png