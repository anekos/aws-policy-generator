
.PHONY: mypy
mypy:
	(source .env/bin/activate ; axe *.py mypy.ini -- mypy %1)

.PHONY: run
run:
	(source .env/bin/activate ; axe *.py -- python %1)
