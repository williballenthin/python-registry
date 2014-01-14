


.PHONY: install_python2
install_python2:
	virtualenv --python=python2 python2
	mkdir python2/working
	cp SYSTEM python2/working/SYSTEM
	cp test.py python2/working/test.py
	python2/bin/pip install python-registry


.PHONY: install_python3
install_python3:
	virtualenv --python=python3 python3
	mkdir python3/working
	cp SYSTEM python3/working/SYSTEM
	cp test.py python3/working/test.py
	python2/bin/pip install python-registry


.PHONY: install_tests
install_tests: install_python2 install_python3


.PHONY: run_test_python2
run_test_python2:
	python2/bin/python python2/working/test.py python2/working/SYSTEM


.PHONY: run_test_python3
run_test_python3:
	python3/bin/python python3/working/test.py python3/working/SYSTEM


.PHONY: run_test
run_test: run_test_python2 run_test_python3

.PHONY: clean
clean:
	rm -rf python2 python3





