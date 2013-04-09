
((function() {

	function initDoc(docId) {

		// @see http://layout.jquery-dev.net/documentation.cfm
		$('body').layout({
			north: {
				resizable: false,
				spacing_open: 2,
				size: 35
			},
			west: {
				size: 300
			}
		});

		var autoreload = false;
		if (window.location.search) {
			var m = window.location.search.match(/autoreload=(\d+)/);
			if (m) {
				autoreload = parseInt(m[1]) * 1000;
				setInterval(function() {
					$.cookie('scroll-offset', $("DIV.ui-layout-center").scrollTop());
					$("DIV.ui-layout-west").addClass("reloading");
					$("DIV.ui-layout-center").addClass("reloading");
					load();
				}, autoreload);
			}
		}

		function positionDocumentToSection(id) {
			window.location.hash = "#" + id;
			$("DIV.ui-layout-center").animate({
			   scrollTop: $("DIV.ui-layout-center").scrollTop() + $("#doc-" + id).offset().top - 50
			}, 250);
		}

		var highlighted = null;
		var shouldHighlight = null;
		var hightlightBufferInterval = null;
		function highlightTocSection(id) {
			shouldHighlight = id;
			if (hightlightBufferInterval) {
				clearTimeout(hightlightBufferInterval);
			}
			hightlightBufferInterval = setTimeout(function() {
				clearTimeout(hightlightBufferInterval);
				if (highlighted) {
					highlighted.removeClass("highlight");
				}
				highlighted = $("#toc-" + shouldHighlight);
				highlighted.addClass("highlight");
				try {
					var frame = $("DIV.ui-layout-west");
				    var offset = frame.scrollTop() + highlighted.offset().top;
				    if(offset > (frame.scrollTop() + frame.innerHeight())) {
				        $("DIV.ui-layout-west").animate({
				        	scrollTop: offset - 50
				        }, 250);
				    } else
				    if (offset < frame.scrollTop() + 50) {
				        $("DIV.ui-layout-west").animate({
				        	scrollTop: offset - frame.innerHeight()
				        }, 250);
				    }
				} catch(err) {}
			}, 250);
		}

		function load() {

			function tocLoaded() {
				$("#toc LI").each(function() {
					var li = $(this);
					li.click(function() {
						var id = li.attr("id").substring(4);
						positionDocumentToSection(id);			
					});
				});
			}
			if (!$("#doc").html()) {
				$.get("/" + docId + "/toc").done(function(data) {
					$("#toc").html(data);
					tocLoaded();
				});
			} else {
				tocLoaded();
			}

			function docLoaded() {
				$("#doc .section-counter-toc").waypoint(function(direction) {
					var active = $(this);
					if (direction === "up") {
					    active = active.prev();
					}
					if (!active.length) {
				        active = $(this);
				    }
					highlightTocSection(active.closest(".section-counter-toc").attr("id").substring(4));
				}, {
					context: "DIV.ui-layout-center",
				});
				$("DIV.ui-layout-west").removeClass("reloading");
				$("DIV.ui-layout-center").removeClass("reloading");
				if (autoreload) {
					$("DIV.ui-layout-center").animate({
			            scrollTop: parseInt($.cookie('scroll-offset'))
			        }, 1);
			    } else
				if (window.location.hash) {
					positionDocumentToSection(window.location.hash.substring(1));
				}
			}
			if (!$("#doc").html()) {
				$.get("/" + docId + "/doc").done(function(data) {
					$("#doc").html(data);
					docLoaded();
				});
			} else {
				docLoaded();
			}
		}

		load();
	}

	$(document).ready(function() {
		if ($('BODY > DIV.ui-layout-center').length === 1) {
			var m = window.location.pathname.match(/\/([^\/]*?)\/?$/);
			if (m) {
				initDoc(m[1]);
			}
		}
	});

})());
