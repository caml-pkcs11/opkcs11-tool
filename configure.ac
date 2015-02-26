define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [1])
define([PACKAGE_VERSION_FIX], [0])

AC_INIT(opkcs11-tool, [PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX])

#Include autoconf macros (ocaml and version comparisons)
AC_CONFIG_MACRO_DIRS([m4])

#bindings_dir="src/bindings-pkcs11"

AC_ARG_WITH(caml-crush, [  --with-caml-crush    indicate caml-crush source directory], [with_caml_crush="$withval"], with_caml_crush=caml-crush)

# Summary helpers
AC_DEFUN([WRITE_TO_FILE],[
printf "%-40s:   %s\n" $2 $3 >> $1
])
AC_DEFUN([SHOW_SUMMARY],[
cat $1 && rm -f $1
])

#Try to detect host_type and set variable
if host_type=`${srcdir}/config.guess`; then :; else
  echo "Cannot guess host type"
  exit 2
fi

# Remove any existing summary file
rm -f ./summary
echo "###########################################" >> ./summary
echo "###               SUMMARY               ###" >> ./summary
echo "###########################################" >> ./summary

##########
# Pass the host to underlying layers
AC_SUBST(host, $host)

##########
# CHECK Make

case $host_type in
   *freebsd*)
	AC_CHECK_PROG(MAKEPROG,gmake,gmake,no)
	if test "$MAKEPROG" == "no"
	then
	  AC_MSG_ERROR(Cannot find GNU gmake.)
	fi
	AC_SUBST(MAKEPROG,$MAKEPROG)
	;;
   *)
	AC_CHECK_PROG(MAKEPROG,make,make,no)
	if test "$MAKEPROG" == "no"
	then
	  AC_MSG_ERROR(Cannot find GNU make.)
	fi
	AC_SUBST(MAKEPROG,$MAKEPROG)
	;;
esac

##########

AC_PROG_OCAML
if test "$OCAMLC" = "no"; then
  AC_MSG_ERROR([You must install the OCaml compiler])
fi

if test "$OCAMLOPT" = "no"; then
  AC_MSG_ERROR([You must install the OCaml compiler])
fi

if test "$OCAMLDEP" = "no"; then
  AC_MSG_WARN([Cannot find ocamldep.])
fi

AC_PROG_CAMLP4
if test "$CAMLP4" = "no"; then
  AC_MSG_ERROR([Cannot find camlp4.])
fi

AC_PROG_FINDLIB
if test "$OCAMLFIND" = "no"; then
  AC_MSG_ERROR([You must install OCaml findlib (the ocamlfind command)])
fi


AC_MSG_NOTICE([Caml Crush source location $with_caml_crush])
AC_SUBST(caml_crush_src, $with_caml_crush)
WRITE_TO_FILE(summary, "Caml Crush source location", "$with_caml_crush")

#Compare version of OCaml to provide an alternative to List.iteri when missing
AX_COMPARE_VERSION([$OCAMLVERSION], [lt], [4.00.1], [need_custom_listiteri=yes], [need_custom_listiteri=false])
if test "$need_custom_listiteri" == "yes"
then
  AC_MSG_NOTICE([OCaml version does not include List.iteri, providing a custom one])
  AC_SUBST(need_custom_listiteri, "-DNEED_CUSTOM_LISTITERI")
  WRITE_TO_FILE(summary, "Custom List.iteri needed", "yes")
else
  AC_SUBST(need_custom_listiteri, "")
  WRITE_TO_FILE(summary, "Custom List.iteri needed", "no")
fi

AC_OUTPUT(Makefile)

SHOW_SUMMARY([summary])
