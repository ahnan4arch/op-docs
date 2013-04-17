
const PATH = require("path");
const FS = require("fs");
const EXPRESS = require("express");
const HBS = require("hbs");
const MARKED = require("marked");
const REQUEST = require("request");

const PORT = 8080;
const MODE = "view";


exports.main = function(callback) {

    var app = EXPRESS();

    return exports.getDocs(function(err, docs) {
        if (err) return callback(err);

        // Github post-commit URL
        // @see https://help.github.com/articles/post-receive-hooks
        // Use: http://docs.openpeer.org/github-post-commit
        app.post(/^\/github-post-commit$/, function(req, res, next) {
            REQUEST("https://raw.github.com/openpeer/op-docs/master/Open%20Peer%20-%20Protocol%20Specification.md", function (error, response, body) {
                if (err) {
                    console.error("[github-post-commit]", err.stack);
                } else
                if (response.statusCode !== 200) {
                    console.error("[github-post-commit]", "response.statusCode: " + response.statusCode);
                } else {
                    try {
                        var path = PATH.join(__dirname, "../Open Peer - Protocol Specification.md");
                        // Sanity check to ensure new file size is within 10% of existing file size.
                        var size = FS.statSync(path).size;
                        var change = Math.floor(((Math.abs(size-body.length)/size)*100) + 1);
                        if (change > 10) {
                            throw new Error("Skip update. File size change " + change + "% for '" + path + "' > 10%");
                        }
                        console.log("[github-post-commit]", "Update '" + path + "' with <= " + change + "% change.");
                        FS.writeFileSync(path, body);
                    } catch(err) {
                        console.error("[github-post-commit]", err.stack);
                    }
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                    return res.end("OK");
                }
            });
        });

        app.get(/^\/([^\/]*)\/(toc|doc)$/, function(req, res, next) {
            return getTemplateData(docs[req.params[0]].filename, req.params[1], function(err, data) {
                if (err) return next(err);
                res.writeHead(200, {
                    "Content-Type": "text/html"
                });
                return res.end(data);
            });
        });

        var hbs = HBS.create();
        app.set("view engine", "hbs");
        app.engine("html", hbs.__express);
        app.engine("hbs", hbs.__express);
        app.set("views", PATH.join(__dirname, "views"));
        app.get(/^\/([^\/]*?)?\/?$/, function(req, res, next) {
            if (req.params[0] && docs[req.params[0]]) {
                return res.render("doc", {
                    title: docs[req.params[0]].label
                });
            } else
            if (!req.params[0]) {
                return res.render("docs", {
                    title: "Open Peer - Documentation",
                    docs: docs
                });
            }
            return next();
        });

        app.get(/^\/([^\/]*)\/(.*?\.png)$/, function(req, res, next) {
            if (req.params[0] && docs[req.params[0]]) {
                var originalUrl = req.url;
                req.url = "/" + req.params[1];
                return EXPRESS.static(PATH.join(__dirname, "..", docs[req.params[0]].dirname))(req, res, function() {
                    req.url = originalUrl;
                    return next.apply(null, arguments);
                });
            }
            return next();
        });

        mountStaticDir(app, /^\/(?:[^\/]*\/)?ui\/(.*)$/, PATH.join(__dirname, "ui"));

        var server = app.listen(PORT);
        console.log("open http://localhost:" + PORT + "/");

        return callback(null, server);
    });
}

exports.getDocs = function (callback) {
    var docs = {};
    FS.readdirSync(PATH.dirname(__dirname)).forEach(function(filename) {
        if (!/\.md$/.test(filename) || filename === "README.md") return;
        var label = filename.replace(/\.md$/, "");
        var id = normalizeId(label);
        docs[id] = {
            id: id,
            dirname: label,
            label: label,
            link: "/" + id + "/",
            filename: filename
        }
    });
    return callback(null, docs);
}

function mountStaticDir(app, route, path) {
    app.get(route, function(req, res, next) {
        var originalUrl = req.url;
        req.url = req.params[0];
        EXPRESS.static(path)(req, res, function() {
            req.url = originalUrl;
            return next.apply(null, arguments);
        });
    });
};

function normalizeId(id) {
    var re = /([a-zA-Z0-9]+)/g;
    return id.replace(/\s+/g, " ").split(" ").map(function(token) {
        var normalized = "";
        var m;
        while (m = re.exec(token)) {
            normalized += m[1];
        }
        if (normalized.length === 0) return "";
        return normalized.slice(0, 1).toUpperCase() + normalized.slice(1);
    }).join("");
}

function processDoc(docFilename, callback) {
    try {
        var tokens = MARKED.lexer(FS.readFileSync(PATH.join(__dirname, "..", docFilename)).toString());
        var html = [];

        var lastDepth = 0;
        var effectiveDepth = 0;
        var lastEffectiveDepth = 0;
        var maxDepth = 2;

        var countersPath = [];
        var sectionsPath = [];
        var usedSectionIds = {};
        function processSection(token) {

            // Some headings jump from depth 1 to depth 3.
            // We want to number headings and generate IDs only for actual levels.
            if (lastDepth !== token.depth) {
                if (token.depth > lastDepth) {
                    effectiveDepth += 1;
                } else {
                    effectiveDepth -= 1;
                }
                if (effectiveDepth > token.depth) {
                    effectiveDepth = token.depth;
                }
                lastDepth = token.depth;                
            }

            // Increment counter for current effective depth
            if (lastEffectiveDepth !== effectiveDepth) {
                if (effectiveDepth > lastEffectiveDepth) {
                    countersPath[effectiveDepth-1] = 1;
                } else {
                    countersPath[effectiveDepth-1] += 1;
                }
                lastEffectiveDepth = effectiveDepth;
            } else {
                countersPath[effectiveDepth-1] += 1;
            }
            countersPath = countersPath.slice(0, effectiveDepth);

            // Generate section ID used for bookmarks
            sectionsPath[effectiveDepth-1] = normalizeId(token.text);
            sectionsPath = sectionsPath.slice(0, effectiveDepth);
            // Ensure there are no duplicate IDs.
            var sectionId = sectionsPath.join("-");
            while (usedSectionIds[sectionId]) {
                sectionId += "_";
            }
            usedSectionIds[sectionId] = true;

            return {
                id: sectionId,
                counter: countersPath.join("."),
                effectiveDepth: effectiveDepth,
                actualDepth: token.depth
            };
        }

        var lastIdentDepth = 0;
        tokens.forEach(function(token) {
            if (token.type !== "heading") return;

            var section = processSection(token);

            var padding = "";
            for (var i=0 ; i<section.actualDepth ; i++) {
                padding += "  ";
            }

            if (section.actualDepth <= maxDepth) {
                if (lastIdentDepth < section.actualDepth) {
                    lastIdentDepth += 1;
                    html.push(padding + "<ul>");
                } else
                if (lastIdentDepth > section.actualDepth) {
                    lastIdentDepth -= 1;
                    html.push(padding + "  </ul>");
                }
                html.push(padding + '  <li id="toc-' + section.id + '">' + token.text + '<span class="counter">' + section.counter + '.</span></li>');
            }
            token.text = '<span id="doc-' + section.id + '" class="section-counter' + ((section.actualDepth <= maxDepth)?"-toc":"") + '">' + section.counter + '.</span>' + token.text;
            if (MODE === "edit") {
                token.text += '<button class="edit" id="edit-' + section.id + '">Edit</button>';
            }
        });
        for (var i=lastIdentDepth ; i>0 ; i--) {
            html.push("</ul>");
        }
        var processed = {
            html: {
                toc: html.join("\n"),
                doc: MARKED.parser(tokens)
            }
        };
        return callback(null, processed);
    } catch(err) {
        return callback(new Error("Parser Error: " + err.stack));
    }
}

function getTemplateData(docFilename, page, callback) {
    if (!docFilename) return callback(new Error("No `docFilename` specified"));
    if (page === "toc" || page === "doc") {
        return processDoc(docFilename, function(err, data) {
            if (err) return callback(err);
            return callback(null, data.html[page]);
        });
    }
    return callback(null);
}


if (require.main === module) {
    exports.main(function(err) {
        if (err) {
            console.error(err.stack);
            process.exit(1);
        }
    });
}
