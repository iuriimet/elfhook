Name:       elfhook
Summary:    bla-bla
Version:    0.0.1
Release:    1
Group:      Base
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz

BuildRequires: cmake

# Requires(post): /sbin/ldconfig
# Requires(postun): /sbin/ldconfig

%description
bla-bla

%prep
%setup -q

%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`

cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DLIB_INSTALL_DIR:PATH=%{_libdir} -DINCLUDE_INSTALL_DIR:PATH=%{_includedir} \
-DFULLVER=%{version} -DMAJORVER=${MAJORVER}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

# %post -p /sbin/ldconfig
# %postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
# %attr(0755,root,root) %{_app_dir}/%{_app_name}
%{_libdir}/libTEST_LIB.so.*
%license LICENSE
