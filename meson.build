project('simplomon', 'cpp', default_options : ['cpp_std=c++20'])

# sqlitedep = dependency('sqlite3', version : '>3')
thread_dep = dependency('threads')
json_dep = dependency('nlohmann_json')
fmt_dep = dependency('fmt', version: '>9', static: true)
curl_dep = dependency('libcurl')

lua_dep = dependency('lua-5.3')

cpphttplib = dependency('cpp-httplib')
# sqlitewriter_dep = dependency('sqlitewriter', static: true)
doctest_dep=dependency('doctest')
simplesockets_dep = dependency('simplesockets', static: true)
# argparse_dep = dependency('argparse', version: '>=3')

executable('simplomon', 'simplomon.cc', 'pushover.cc', 'minicurl.cc', 'dnsmon.cc', 'record-types.cc', 'dnsmessages.cc', 'dns-storage.cc', 'netmon.cc', 'luabridge.cc',
	dependencies: [curl_dep, json_dep, fmt_dep, cpphttplib, 
	simplesockets_dep, lua_dep])


executable('testrunner', 'testrunner.cc', 'pushover.cc', 'minicurl.cc', 'dnsmon.cc', 'record-types.cc', 'dnsmessages.cc', 'dns-storage.cc', 'netmon.cc', 'luabridge.cc',
	dependencies: [doctest_dep, curl_dep, json_dep, fmt_dep, cpphttplib, 
	simplesockets_dep, lua_dep])

