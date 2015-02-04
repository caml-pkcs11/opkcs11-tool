top_dir = $(PWD)
caml_crush_dir = caml-crush
bindings_dir = $(caml_crush_dir)/src/bindings-pkcs11
x509_dir=./x509/
CFLAGS = -I $(bindings_dir) 
LDFLAGS = -package "str,unix" -cclib -lcamlidl -cclib -L$(bindings_dir) -cclib -L./ -cclib -lmyssl -cclib -lssl -cclib -lcrypto
LDFLAGS_STANDALONE= -package "str,unix" -cclib -lcamlidl -cclib -L$(bindings_dir) -cclib -L./
opkcs11_binary=opkcs11-tool


all: build_bindings_standalone opkcs11_tool_standalone

build_bindings_standalone:
	cd $(caml_crush_dir) ;\
	./autogen.sh ;\
	./configure --without-caml-crush --with-idlgen
	cd $(bindings_dir);\
	make -f Makefile.standalone;
	echo "Binding compilation done, cleanup up modified files";
	#FIXME: The following is ugly, it restores IDL-generated files
	cd $(caml_crush_dir);\
	git checkout src/bindings-pkcs11/pkcs11.h;\
	git checkout src/bindings-pkcs11/pkcs11.ml;\
	git checkout src/bindings-pkcs11/pkcs11_stubs.c

ssl_parse:
	gcc -g -fPIC -c  ssl_stubs.c -I/usr/local/lib/ocaml
	ocamlopt -pp "camlp4o pa_macro.cmo -DWITH_OCAML_SSL" -g -c ssl.mli ssl.ml
	ocamlmklib -o myssl ssl.cmx ssl_stubs.o -cclib -L/usr/local/lib/ocaml -cclib -lcamlidl

opkcs11_tool_ssl: build_bindings_standalone ssl_parse
	ocamlfind ocamlopt -pp "camlp4o pa_macro.cmo -DWITH_OCAML_SSL" $(CFLAGS) -c p11_common.ml p11_objects.ml p11_infos.ml p11_crypto.ml
	ocamlfind ocamlopt $(CFLAGS) -c opkcs11_tool.ml
	ocamlfind ocamlopt -linkpkg myssl.cmxa $(bindings_dir)/pkcs11_standalone.cmxa p11_common.cmx p11_objects.cmx p11_infos.cmx p11_crypto.cmx opkcs11_tool.cmx $(LDFLAGS) -o $(opkcs11_binary)

opkcs11_tool_standalone:
	cd $(x509_dir) && ocamlopt -c helpers.ml oids.ml asn1.ml pkcs1_8.ml x509.ml && cd -
	ocamlfind ocamlopt -pp "camlp4o pa_macro.cmo -DWITH_OCAML_X509" $(CFLAGS) -I $(x509_dir) -c p11_common.ml ssl.mli ssl.ml p11_objects.ml p11_infos.ml p11_crypto.ml
	ocamlfind ocamlopt $(CFLAGS) -c opkcs11_tool.ml
	ocamlfind ocamlopt -linkpkg $(bindings_dir)/pkcs11_standalone.cmxa $(x509_dir)/helpers.cmx $(x509_dir)/oids.cmx $(x509_dir)/asn1.cmx $(x509_dir)/pkcs1_8.cmx $(x509_dir)/x509.cmx p11_common.cmx ssl.cmx p11_objects.cmx p11_infos.cmx p11_crypto.cmx opkcs11_tool.cmx $(LDFLAGS_STANDALONE) -o $(opkcs11_binary)


clean:
	cd $(caml_crush_dir);\
	make clean;\
	./autoclean.sh
	@rm -f *.cmi *.cmx *.o *.cmo *~ *.cmxa *.a *.cma *.so
	@rm -f $(opkcs11_binary)
	@rm -f $(x509_dir)/*.cmi $(x509_dir)/*.cmx $(x509_dir)/*.o $(x509_dir)/*.cmo $(x509_dir)/*~ $(x509_dir)/*.opt $(x509_dir)/*.cmxa $(x509_dir)/*.a $(x509_dir)/*.cma $(x509_dir)/*.so
