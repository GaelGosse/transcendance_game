var c = document.getElementById('board');
var ctx = c.getContext("2d")
var stop = true;

// canva
var w_canva = 1000;
var h_canva = 620;

// ball
var x_ball = w_canva / 2;
var y_ball = h_canva / 2;
var x_ball_save = w_canva / 2;
var y_ball_save = h_canva / 2;
var x_speed = -5;
var y_speed = -5;
var ballRad = 10;

// player
var wpallet = 10;
var hpallet = 120;
var l_player = h_canva / 2;
var r_player = h_canva / 2;

// stats
var start_time = 0;
var end_time = 0;
var still_alive = Date.now();
var exchanges = 0;

var end_score = 1;
var red_score = 0;
var blue_score = 0;

var red_display = document.getElementById('red_score');
var blue_display = document.getElementById('blue_score');

function drawRect(x, y, w, h, color) {
	ctx.beginPath();
	ctx.fillStyle = color;
	ctx.fillRect(x, y, w, h);
}

function drawCircle(x, y, rad, color) {
	ctx.beginPath();
	ctx.fillStyle = color;
	ctx.arc(x, y, rad, 0, Math.PI*2, true);
	ctx.fill();
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

if (id_party == -1)
{
	var path = window.location.pathname;
	var id_party = path.match(/\/pong_page\/(\d+)\//)
	if (id_party)
		id_party = id_party[1];
}
function send_score(id_party) {
	if (id_party == -1)
	{
		var path = window.location.pathname;
		var id_party = path.match(/\/pong_page\/(\d+)\//)
		if (id_party)
			id_party = id_party[1];
	}
	console.log("send: ", id_party, red_score, blue_score);
	$.ajax({
		url: '/scoring/' + id_party + '/',
		type: 'POST',
		async: false,
		beforeSend: function(xhr) {
			xhr.setRequestHeader("X-CSRFToken", csrftoken);
		},
		data: {
			'red_score': red_score,
			'blue_score': blue_score,
			'game_time': end_time - start_time,
		},
		success: function() {
			// would you like to restart ?
		}
	});
}

function move() {
	x_ball += x_speed;
	y_ball += y_speed;

	var yl_top = l_player - hpallet / 2;
	var yl_bottom = l_player + hpallet / 2;
	var yr_top = r_player - hpallet / 2;
	var yr_bottom = r_player + hpallet / 2;

	if (x_ball - ballRad <= wpallet
	&& y_ball >= yl_top && y_ball <= yl_bottom
	&& x_speed < 0)
	{
		// left
		x_speed *= -1;
		exchanges++;
	}
	else if (x_ball + ballRad >= w_canva - wpallet
	&& y_ball >= yr_top && y_ball <= yr_bottom
	&& x_speed > 0)
	{
		// right
		x_speed *= -1;
		exchanges++;
	}
	else if (y_ball <= (0 + ballRad-1) || y_ball >= (h_canva - ballRad-1))
		y_speed *= -1;
	else if (x_ball <= (0 - ballRad-1))
	{
		stop = true;
		red_score += 1;

		// the one who serves
		if (x_speed > 0)
			x_speed *= -1;

		red_display.textContent = red_score;
		red_display.classList.add('scored');
		setTimeout(() => {
			red_display.classList.remove('scored');
		}, 2000);
	if (red_score < end_score)
		setTimeout(restart, 1000);
	else
		{
			end_time = Date.now();
			document.getElementById("win").style.opacity = "1";
			document.getElementById("win").classList.add('blue_win');
			red_display.classList.add('final_score');
			send_score();
		}
	}
	else if (x_ball >= (w_canva + ballRad+1))
	{
		stop = true;
		blue_score += 1;

		// the one who serves
		if (x_speed < 0)
			x_speed *= -1;

		blue_display.textContent = blue_score;
		blue_display.classList.add('scored');
		setTimeout(() => {
			blue_display.classList.remove('scored');
		}, 2000);
	if (blue_score < end_score)
		setTimeout(restart, 1000);
	else
		{
			end_time = Date.now();
			document.getElementById("win").style.opacity = "1";
			document.getElementById("win").classList.add('red_win');
			blue_display.classList.add('final_score');
			send_score();
		}
	}
}

function restart() {
	x_ball = w_canva / 2;
	y_ball = h_canva / 2;
	x_ball_save = w_canva / 2;
	y_ball_save = h_canva / 2;
	if (x_speed < 0)
		x_speed = -5;
	else
		x_speed = 5;
	y_speed = -5;

	wpallet = 10;
	hpallet = 120;
	l_player = h_canva / 2;
	r_player = h_canva / 2;
	document.getElementById("win").style.opacity = "0"
	document.getElementById("win").classList.remove('red_win')
	document.getElementById("win").classList.remove('blue_win')
	blue_display.classList.remove('final_score')
	display();

	setTimeout(() => {
		stop = false;
		frame()
	}, 2000);
}

function display() {
	// console.log(x_speed, y_speed);
	ctx.clearRect(0, 0, w_canva, h_canva);
	drawRect(0, l_player - hpallet / 2, wpallet, hpallet, "#F04");
	drawRect(w_canva - wpallet, r_player - hpallet / 2, wpallet, hpallet, "#09F");
	drawCircle(x_ball_save, y_ball_save, 10, "rgba(255,255,255,0.5)");
	drawCircle(x_ball, y_ball, 10, "#FFF");
}

function frame() {
	x_ball_save = x_ball;
	y_ball_save = y_ball;
	move();
	display();
	if (!stop)
		requestAnimationFrame(frame);
}

display();
setTimeout(() => {
	stop = false;
	start_time = Date.now()

	frame();
}, 5000);

// window.onbeforeunload = function() {
// 	send_score();
// }

document.addEventListener('keydown', (e)=>
{
	console.log("4 id_party: ", id_party)
	still_alive = Date.now();
	if (!stop && e.keyCode == 38 && (r_player - hpallet / 2) > 0)
		r_player -= 25; // up
	if (!stop && e.keyCode == 40 && (r_player + hpallet / 2) < h_canva)
		r_player += 25; // down

	if (!stop && e.keyCode == 90 && (l_player - hpallet / 2) > 0)
		l_player -= 25; // z
	if (!stop && e.keyCode == 83 && (l_player + hpallet / 2) < h_canva)
		l_player += 25; // s
})

// let stillAliveInterval = setInterval(() => {
// 	// if (still_alive )
// 	if (Date.now()/1000 - still_alive/1000 > 15)
// 	{
// 		clearInterval(stillAliveInterval)
// 		stop = true;
// 		send_score(id_party);
// 		document.querySelector('#pop_up').style.display = "block"
// 		document.querySelector('#pop_up').textContent = "Your are inactive, your game is ended";
// 		setTimeout(() => {
// 			document.querySelector('#pop_up').style.opacity = "1";
// 		}, 200);

// 		// setTimeout(() => {
// 		// 	document.querySelector('#pop_up').style.opacity = "0";
// 		// 	setTimeout(() => {
// 		// 		document.querySelector('#pop_up').style.display = "block";
// 		// 	}, 350);
// 		// }, 5000);
// 	}
// }, 4000);
