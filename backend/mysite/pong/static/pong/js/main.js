// // IMRANE
// document.addEventListener('DOMContentLoaded', () => {
//     console.log('Script main.js est chargé');


//     window.addEventListener('popstate', event => {
//         console.log("event = ", event);
//         if (event.state && event.state.path) {
//             console.log('Navigating to:', event.state.path);
//             const path = event.state.path;
//             currentIndex = customHistory.indexOf(path); // Synchronize custom history index
//             // var i = customHistory.length;
//             // while (i > 0)
//             // {
//             //     if (customHistory[i] === event.state.path)
//             //     {
//             //         currentIndex = i;
//             //         break;
//             //     }
//             //     i--;
//             // }
//             console.log("current index apres indexOf", currentIndex);
//             loadContent(path, false); // Load content without adding to history
//         } else {
//             // Cas où il n'y a pas d'état, on peut utiliser la location actuelle
//             console.log('Navigating to current path:', window.location.pathname);
//             loadContent(window.location.pathname, false); // Load content without adding to history
//         }
//     });

//     document.addEventListener('click', event => {
//         const link = event.target.closest('a');
//         console.log("Fonction principale : link =", link);
//         if (link) {
//             event.preventDefault();
//             const path = new URL(link.href).pathname;
//             console.log("Fonction principale : path =", path);
//             //window.history.pushState({}, '', path);
//             loadContent(path, true);
//         }
//     });


//     // Gestionnaire d'événements pour les formulaires
//     document.addEventListener('submit', event => {
//         console.log("target = ", event.target.tagName);
//         if (event.target.tagName === 'FORM') {
//             event.preventDefault();
//             submitForm(event.target);
//         }
//     });
// });



// // DEFINITIONB DES FONCTIONS

// var customHistory = [];
// var currentIndex = -1;


// function loadContent(path, addToHistory) {
//     console.log("addTohistory = ", addToHistory);
//     console.log('Loading content from:', path);
//     var toggle = false;
//     fetch(path, {
//         headers: { 'X-Requested-With': 'XMLHttpRequest' }
//     })
//     .then(response => response.text())
//     .then(text => {
//         console.log('Raw response:', text);
//         try {
//             const data = JSON.parse(text);
//             console.log("data =", data);

//             if (data.html) {
//                 document.getElementById('app').innerHTML = data.html;
//                 if (addToHistory) {
//                     if (currentIndex === customHistory.length - 1)
//                     {
//                         if (customHistory[currentIndex] != data.url)
//                         {
//                             customHistory.push(data.url);
//                             currentIndex++;
//                             toggle = true;
//                         }
//                     }
//                     else
//                     {
//                         customHistory = customHistory.slice(0, currentIndex + 1);
//                         console.log("Custom history quand on tronque l'historique", customHistory)
//                         customHistory.push(data.url);
//                         currentIndex = customHistory.length - 1;
//                     }
//                     if (toggle === true)
//                         window.history.pushState({ path: data.url }, '', data.url);
//                 }
//                 console.log("customHistory =", customHistory);
//                 console.log("currentIndex =", currentIndex);
//             } else {
//                 console.error('data.html is undefined');
//                 document.getElementById('app').innerHTML = text;
//             }
//         } catch (error) {
//             console.error('Error parsing JSON:', error);
//             document.getElementById('app').innerHTML = text;
//         }
//     })
//     .catch(error => console.error('Error loading content:', error));
// }


// // var customHistory = [];

// // function loadContent(path) {
// //     console.log('Loading content from:', path);
// //     fetch(path, {
// //         headers: { 'X-Requested-With': 'XMLHttpRequest' }
// //     })
// //     .then(response => response.text()) // Change to response.text() to debug
// //     .then(text => {
// //         console.log('Raw response:', text); // Log the raw response
// //         try {
// //             const data = JSON.parse(text); // Parse JSON manually
// //             console.log("data =", data);
// //             if (data.url)
// //             {
// //                 console.log("data url =", data.url);
// //                 console.log("Chargement URL ok")
// //                 customHistory.push(data.url);
// //                 printCustomHistory();
// //                 window.history.pushState({path : data.url}, '', data.url);
// //             }
// //             else
// //             {
// //                 console.log("Url not catched or defined");
// //             }
// //             if (data.html)
// //                 document.getElementById('app').innerHTML = data.html;
// //             else
// //                 console.log("error loading html");
// //             //attachFormListeners();
// //             //attachLinkListeners();
// //         } catch (error) {
// //             console.error('Error parsing JSON:', error);
// //             document.getElementById('app').innerHTML = text; // Display the HTML in the app div for debugging
// //         }
// //     })
// //     .catch(error => console.error('Error loading content:', error));
// // }




// function printCustomHistory()
// {
//     console.log("Custom History =", customHistory);
// }


// function submitForm(form) {
//     const formData = new FormData(form);
//     console.log("Submitting form:", form.action);
//     fetch(form.action, {
//         method: form.method || 'POST',
//         body: formData,
//         headers: { 'X-Requested-With': 'XMLHttpRequest' }
//     })
//     .then(response => response.text()) // Change to response.text() to debug
//     .then(text => {
//         console.log('Raw response:', text); // Log the raw response
//         try {
//             const data = JSON.parse(text); // Parse JSON manually
//             console.log("Parsed response:", data);
//             window.history.pushState({}, '', data.url);
//             document.getElementById('app').innerHTML = data.html;
//             //attachFormListeners();
//             //attachLinkListeners();
//         } catch (error) {
//             console.error('Error parsing JSON:', error);
//             document.getElementById('app').innerHTML = text; // Display the HTML in the app div for debugging
//         }
//     })
//     .catch(error => console.error('Error submitting form:', error));
// }
var checkGameStatusInterval;
var searchingMatchInterval;

document.addEventListener('DOMContentLoaded', () => {
	console.log('Script main.js est chargé');

	// script_array = Array.from(document.querySelector('body').querySelectorAll("script"));
	// // console.log("script_array: ", script_array);
	// script_array.forEach((script) => {
	// 	var new_script = document.createElement('script');
	// 	new_script.innerHTML = script.textContent;
	// 	script.remove();
	// 	document.getElementById('app').appendChild(new_script);
	// })

	window.addEventListener('popstate', event => {
		console.log("event = ", event);
		if (event.state && event.state.path) {
			console.log('Navigating to:', event.state.path);
			const path = event.state.path;
			currentIndex = customHistory.indexOf(path); // Synchronize custom history index
			// var i = customHistory.length;
			// while (i > 0)
			// {
			//     if (customHistory[i] === event.state.path)
			//     {
			//         currentIndex = i;
			//         break;
			//     }
			//     i--;
			// }
			console.log("current index apres indexOf", currentIndex);
			loadContent(path, false); // Load content without adding to history
		} else {
			// Cas où il n'y a pas d'état, on peut utiliser la location actuelle
			console.log('Navigating to current path:', window.location.pathname);
			loadContent(window.location.pathname, false); // Load content without adding to history
		}
	});

	document.addEventListener('click', event => {
		const link = event.target.closest('a');
		// console.log("Fonction principale : link =", link);
		if (link) {
			event.preventDefault();
			const path = new URL(link.href).pathname;
			// console.log("Fonction principale : path =", path);
			//window.history.pushState({}, '', path);
			loadContent(path, true);
		}
	});


	// Gestionnaire d'événements pour les formulaires
	document.addEventListener('submit', event => {
		console.log("target = ", event.target.tagName);
		if (event.target.tagName === 'FORM') {
			event.preventDefault();
			submitForm(event.target, true);
		}
	});
});



// DEFINITIONB DES FONCTIONS

var customHistory = [new URL(window.location.href).pathname];
var currentIndex = 0;

function send_score_quit(id_party) {
	if (id_party)
	{
		$.ajax({
			url: '/scoring/' + id_party + '/',
			type: 'POST',
			async: false,
			beforeSend: function(xhr) {
				xhr.setRequestHeader("X-CSRFToken", csrftoken);
			},
			data: {
				'red_score': 0,
				'blue_score': 0,
				'exchanges': 0,
				'game_time': 0,
			},
			success: function() {
				// would you like to restart ?
			}
		});
	}
}

function getCookie(name) {
	var cookieValue = null;
	if (document.cookie && document.cookie !== '') {
		var cookies = document.cookie.split(';');
		for (var i = 0; i < cookies.length; i++) {
			var cookie = jQuery.trim(cookies[i]);
			if (cookie.substring(0, name.length + 1) === (name + '=')) {
				cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
				break;
			}
		}
	}
	return cookieValue;
}

var csrftoken = getCookie('csrftoken');

function loadContent(path, addToHistory) {
	// console.log("addTohistory = ", addToHistory);
	console.log('Loading content from:', path);
	var i_clear_interval = -1;
	while (++i_clear_interval < 1000)
		clearInterval(i_clear_interval);

	if (customHistory.length > 1
	&& customHistory[customHistory.length - 1].indexOf('pong_page') != -1)
	{
		var id_party = customHistory[customHistory.length - 1].match(/\/pong_page\/(\d+)\//)
		if (id_party)
			id_party = id_party[1];
		console.log("last id party: ", id_party);
		send_score_quit(id_party);
	}

	var toggle = false;
	fetch(path, {
		headers: { 'X-Requested-With': 'XMLHttpRequest' }
	})
	.then(response => response.text())
	.then(text => {
		// console.log('Raw response:', text);
		try {
			const data = JSON.parse(text);
			// console.log("data =", data);
			if (data.html) {
				document.getElementById('app').innerHTML = data.html;
				script_array = Array.from(document.getElementById('app').querySelectorAll("script"));
				script_array.forEach((script) => {
					var new_script = document.createElement('script');
					new_script.innerHTML = script.textContent;
					for (var attr of script.attributes) {
						new_script.setAttribute(attr.name, attr.value);
					}
					script.remove();
					document.getElementById('app').appendChild(new_script);
				})
				if (addToHistory) {
					if (currentIndex === customHistory.length - 1)
					{
						if (customHistory[currentIndex] != data.url)
						{
							customHistory.push(data.url);
							currentIndex++;
							toggle = true;
						}
					}
					else
					{
						customHistory = customHistory.slice(0, currentIndex + 1);
						console.log("Custom history quand on tronque l'historique", customHistory)
						customHistory.push(data.url);
						currentIndex = customHistory.length - 1;
					}
					if (toggle === true)
						window.history.pushState({ path: data.url }, '', data.url);
				}
				console.log("customHistory =", customHistory);
				if (customHistory.length > 2
				&& customHistory[customHistory.length - 1].indexOf('pong_page') == -1
				&& customHistory[customHistory.length - 2].indexOf('waiting_pong') != -1)
				{
					$.ajax({
						url: '/stop_waiting/',
						type: 'POST',
						async: false,
						beforeSend: function(xhr) {
							xhr.setRequestHeader("X-CSRFToken", csrftoken);
						},
						success: function() {}
					});
				}
			}
			else
			{
				console.error('data.html is undefined');
				document.getElementById('app').innerHTML = text;
			}
		} catch (error) {
			console.error('Error parsing JSON:', error);
			document.getElementById('app').innerHTML = text;
		}
	})
	.catch(error => console.error('Error loading content:', error));
}


// var customHistory = [];

// function loadContent(path) {
//     console.log('Loading content from:', path);
//     fetch(path, {
//         headers: { 'X-Requested-With': 'XMLHttpRequest' }
//     })
//     .then(response => response.text()) // Change to response.text() to debug
//     .then(text => {
//         console.log('Raw response:', text); // Log the raw response
//         try {
//             const data = JSON.parse(text); // Parse JSON manually
//             console.log("data =", data);
//             if (data.url)
//             {
//                 console.log("data url =", data.url);
//                 console.log("Chargement URL ok")
//                 customHistory.push(data.url);
//                 printCustomHistory();
//                 window.history.pushState({path : data.url}, '', data.url);
//             }
//             else
//             {
//                 console.log("Url not catched or defined");
//             }
//             if (data.html)
//                 document.getElementById('app').innerHTML = data.html;
//             else
//                 console.log("error loading html");
//             //attachFormListeners();
//             //attachLinkListeners();
//         } catch (error) {
//             console.error('Error parsing JSON:', error);
//             document.getElementById('app').innerHTML = text; // Display the HTML in the app div for debugging
//         }
//     })
//     .catch(error => console.error('Error loading content:', error));
// }




function printCustomHistory()
{
	console.log("Custom History =", customHistory);
}


function submitForm(form, addToHistory) {
	const formData = new FormData(form);
	var toggle = false;
	console.log("Submitting form:", form.action);
	fetch(form.action, {
		method: form.method || 'POST',
		body: formData,
		headers: { 'X-Requested-With': 'XMLHttpRequest' }
	})
	.then(response => response.text()) // Change to response.text() to debug
	.then(text => {
		// console.log('Raw response:', text); // Log the raw response
		try {
			const data = JSON.parse(text); // Parse JSON manually
			console.log("Parsed response:", data);
			if (data.html)
			{
				document.getElementById('app').innerHTML = data.html;
				// console.log("big =", document.getElementById('app'));
				script_array = Array.from(document.getElementById('app').querySelectorAll("script"));
				console.log("script_maarray =", script_array);
				script_array.forEach((script) => {
					var new_script = document.createElement('script');
					new_script.innerHTML = script.textContent;
					script.remove();
					document.body.appendChild(new_script);
				})
			}
			if (addToHistory) {
				if (currentIndex === customHistory.length - 1)
				{
					if (customHistory[currentIndex] != data.url)
					{
						customHistory.push(data.url);
						currentIndex++;
						toggle = true;
					}
				}
				else
				{
					customHistory = customHistory.slice(0, currentIndex + 1);
					console.log("Custom history quand on tronque l'historique", customHistory)
					customHistory.push(data.url);
					currentIndex = customHistory.length - 1;
				}
				if (toggle === true)
					window.history.pushState({ path: data.url }, '', data.url);
			}
			else
			{
				console.error('data.html is undefined');
				document.getElementById('app').innerHTML = text;
			}
		} catch (error) {
			console.error('Error parsing JSON:', error);
			document.getElementById('app').innerHTML = text; // Display the HTML in the app div for debugging
		}
	})
	.catch(error => console.error('Error submitting form:', error));
}
