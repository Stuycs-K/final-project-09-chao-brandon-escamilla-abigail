usage:
	echo "read directions"

run: AES.class
	@java AES.java $(ARGS)

AES.class: AES.java
	@javac AES.java

AES: run

clean:
	@rm *.class