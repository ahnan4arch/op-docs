
const PATH = require("path");
const FS = require("fs-extra");
const SERVER = require("./server");
const WAITFOR = require("waitfor");
const REQUEST = require("request");


module.exports = function(grunt) {

  var config = {
    pkg: grunt.file.readJSON('package.json'),
    copy: {
      main: {
        files: [
          {expand: true, cwd: 'ui', src: '*', dest: '../<%= doc.dirname %>/_dist/'}
        ]
      }
    }
  };


  grunt.loadNpmTasks('grunt-contrib-copy');


  grunt.registerTask('build-doc', function(id) {
    config.doc = config.docs[id];
    grunt.initConfig(config);
    FS.removeSync(PATH.join(__dirname, "..", config.doc.dirname, "_dist"));
    FS.writeFileSync(PATH.join(__dirname, "..", config.doc.dirname + ".html"), config.doc.html);
    grunt.task.run('copy');
  });


  grunt.registerTask('build', function() {

    var done = this.async();

    return SERVER.main(function(err, server) {
      if (err) return done(err);

      return SERVER.getDocs(function(err, docs) {
        if (err) return done(err);

        var waitfor = WAITFOR.serial(function(err) {
          if (err) return done(err);

          grunt.initConfig(config);

          return server.close(function() {
            return done(null);
          });
        });

        config.docs = {};
        for (var id in docs) {

          waitfor(id, function(id, done) {

            config.docs[id] = {
              id: docs[id].id,
              dirname: docs[id].dirname,
              html: null
            };

            return REQUEST("http://localhost:8080/" + id, function(err, response) {
              if (err) return done(err);

              config.docs[id].html = response.body;
              config.docs[id].html = config.docs[id].html.replace(/(\ssrc=")ui(.*?.js")/g, "$1" + docs[id].dirname + "/_dist$2");
              config.docs[id].html = config.docs[id].html.replace(/(\shref=")ui(.*?.css")/g, "$1" + docs[id].dirname + "/_dist$2");

              return REQUEST("http://localhost:8080/" + id + "/toc", function(err, response) {
                if (err) return done(err);

                config.docs[id].html = config.docs[id].html.replace('<div id="toc"></div>', '<div id="toc">' + response.body + '</div>');

                return REQUEST("http://localhost:8080/" + id + "/doc", function(err, response) {
                  if (err) return done(err);

                  config.docs[id].html = config.docs[id].html.replace('<div id="doc"></div>', '<div id="doc">' + response.body + '</div>');

                  config.docs[id].html = config.docs[id].html.replace(/(\ssrc=")(.*?.png")/g, "$1" + docs[id].dirname  + "/$2");

                  // Schedule task to run.
                  grunt.task.run('build-doc:' + id);

                  return done();
                });
              });
            });
          });
        }
        waitfor();
      });
    });
  });
};
