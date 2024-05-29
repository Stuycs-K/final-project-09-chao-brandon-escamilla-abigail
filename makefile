usage:
	echo "read directions"

run: AdvancedEncryptionStandard.class
	@java AdvancedEncryptionStandard.java $(ARGS)

AdvancedEncryptionStandard.class: AdvancedEncryptionStandard.java
	@javac AdvancedEncryptionStandard.java

AES: run

clean:
	@rm *.class