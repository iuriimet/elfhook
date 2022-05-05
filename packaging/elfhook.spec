Name:       elfhook
Version:    1.0.0
Release:    1
Summary:    bla-bla
Group:      Base
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz

BuildRequires: gcc
BuildRequires: cmake
BuildRequires: pkgconfig(dlog)

%define _project_name elfhook
%define _installdir /usr
%define _app_dir %{_installdir}/apps/%{_project_name}
%define _app_name %{_project_name}
%define _lib_dir %{_installdir}/local/lib
%define _libelfmem_name libelfmem.so
%define _libelffuzz_name libelffuzz.a
%define _libtest_name libtest.so
%define _inc_dir %{_installdir}/local/include
%define _manifestdir %{_installdir}/share/packages

%description
bla-bla

%prep
%setup -q

%build
%{!?build_type:%define build_type "RELEASE"}

cmake -H./ -B./build-gbs \
    -DCMAKE_BUILD_TYPE=%{build_type} \
    -DINSTALLDIR=%{_installdir} \
    -DBIN_DIR=%{_app_dir} \
    -DLIB_DIR=%{_lib_dir} \
    -DINC_DIR=%{_inc_dir} \
    -DMANIFESTDIR=%{_manifestdir} \
    -D__TIZEN__=1 \
    #eol

%install
cd build-gbs
%make_install
install -m 644 libraries/elffuzz/%{_libelffuzz_name} %{buildroot}/%{_lib_dir}/%{_libelffuzz_name}

%clean
rm -rf %{buildroot}

%files
%attr(0755,root,root) %{_app_dir}/%{_app_name}
%attr(0644,root,root) %{_lib_dir}/%{_libelfmem_name}
%attr(0644,root,root) %{_lib_dir}/%{_libelffuzz_name}
%attr(0644,root,root) %{_lib_dir}/%{_libtest_name}
%attr(0644,root,root) %{_inc_dir}/elfmem/*.h
%attr(0644,root,root) %{_inc_dir}/elffuzz/*.h
%attr(0644,root,root) %{_inc_dir}/test/*.h
%manifest %{_manifestdir}/%{_app_name}.manifest




%package    elfmem
Version:    1.0.0
Release:    1
Summary:    bla-bla
Group:      Base

%description elfmem
bla-bla

%files elfmem
%attr(0644,root,root) %{_lib_dir}/%{_libelfmem_name}
%attr(0644,root,root) %{_inc_dir}/elfmem/*.h
%manifest %{_manifestdir}/elfmem.manifest




%package    elffuzz
Version:    1.0.0
Release:    1
Summary:    bla-bla
Group:      Base

%description elffuzz
bla-bla

%files elffuzz
%attr(0644,root,root) %{_lib_dir}/%{_libelffuzz_name}
%attr(0644,root,root) %{_inc_dir}/elffuzz/*.h
%manifest %{_manifestdir}/elffuzz.manifest
