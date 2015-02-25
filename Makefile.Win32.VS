#You need to adapt :
#  * CAML_INC to the location of the OCaml package on your system
#  * bindings_dir to the location of the compiled OCaml PKCS#11 bindings for Windows

CAML_INC=C:\ocamlms64\lib

bindings_dir = ..\caml-crush\src\bindings-pkcs11
x509_dir=x509
LDFLAGS_STANDALONE= -cclib -L$(CAML_INC) -cclib ole32.lib -cclib -lcamlidl -ccopt -lcamlidl -cclib -L$(bindings_dir) -cclib -L.\

# Output LIB
OPKCS11TOOL=opkcs11_tool_standalone

TARGETS=$(OPKCS11TOOL).exe
TRASH=*.pdb *.lib *.exp *.idb *.manifest *.cmi *.cmx *.o *.cmo *~ *.opt *.cmxa *.a *.cma *.so *.obj

.SUFFIXES: .c .obj .OBJ .rc .res .Obj .dll *.cmxa 

.rc.res:
	rc $(DEFINES) $<

all:	$(TARGETS)

clean:
	del  $(TARGETS) $(PKCS11_OBJ) $(TRASH)


#Compile and link
$(OPKCS11TOOL).opt: $(PKCS11_OBJ)
	cd $(x509_dir) && ocamlopt -c helpers.ml oids.ml asn1.ml pkcs1_8.ml x509.ml && cd ..
	ocamlopt -pp "camlp4o pa_macro.cmo -DWIN32 -DWITH_OCAML_X509" -I $(bindings_dir) -I $(x509_dir) -c ecc_helper.ml p11_common.ml ssl.mli ssl.ml p11_objects.ml p11_infos.ml p11_crypto.ml p11_templates.ml
	ocamlopt -I $(bindings_dir) -c opkcs11_tool.ml
	ocamlopt $(CAML_INC)\str.cmxa $(bindings_dir)\libpkcs11_standalone.lib $(bindings_dir)\pkcs11_standalone.cmxa $(x509_dir)\helpers.cmx $(x509_dir)\oids.cmx $(x509_dir)\asn1.cmx $(x509_dir)\pkcs1_8.cmx $(x509_dir)\x509.cmx ecc_helper.cmx p11_common.cmx ssl.cmx p11_objects.cmx p11_infos.cmx p11_crypto.cmx p11_templates.cmx opkcs11_tool.cmx $(LDFLAGS_STANDALONE) -o $(OPKCS11TOOL).exe
