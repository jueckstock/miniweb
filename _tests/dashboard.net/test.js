(() => {
	window.addEventListener('load', () => {
		const url = new URL(window.location);
		if (url.protocol !== "https:") {
			fetch("https://dashboard.net/test.js", { mode: 'no-cors' })
				.then((response) => {
					url.protocol = "https:";
					window.location = url;
				})
				.catch((err) => {
					const slot = document.querySelector('div#message-slot');
					const msg = document.createElement('div');
					msg.classList.add('notice');
					msg.innerText = "You need to install miniweb's root CA cert in order to use TLS!";
					slot.replaceWith(msg);
					console.error("BOOM", err);
				});
		}
		
	});
})();
