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
%define _app_name %{_project_name}
%define _app_dir /usr/apps/%{_project_name}
%define _lib_name libtest.so
%define _lib_dir /usr/local/lib
%define _manifestdir /usr/share/packages

%description
bla-bla

%prep
%setup -q

%build
%{!?build_type:%define build_type "RELEASE"}

cmake -H./ -B./build-gbs \
    -DCMAKE_BUILD_TYPE=%{build_type} \
    -DBIN_DIR=%{_app_dir} \
    -DLIB_DIR=%{_lib_dir} \
    -DMANIFESTDIR=%{_manifestdir} \
    -DBIN_DIR=%{_app_dir} \
    -D__TIZEN__=1 \
    #eol

%install
cd build-gbs
%make_install

%clean
rm -rf %{buildroot}

%files
%attr(0755,root,root) %{_app_dir}/%{_app_name}
%attr(0644,root,root) %{_lib_dir}/%{_lib_name}
%manifest %{_manifestdir}/%{_app_name}.manifest
