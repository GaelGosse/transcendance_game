
let c = document.getElementById('board');
let ctx = c.getContext("2d")
let stop = true;

// canva
let w_canva = 1000;
let h_canva = 620;

// ball
let x_ball = w_canva / 2;
let y_ball = h_canva / 2;
let x_ball_save = w_canva / 2;
let y_ball_save = h_canva / 2;
let x_speed = -5;
let y_speed = -5;
let ballRad = 10;

// player
let wpallet = 10;
let hpallet = 120;
let l_player = h_canva / 2;
let r_player = h_canva / 2;

let red_score = 0;
let blue_score = 0;
let red_display = document.getElementById('red_score');
let blue_display = document.getElementById('blue_score');

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

function move() {
	x_ball += x_speed;
	y_ball += y_speed;


	let yl_top = l_player - hpallet / 2;
	let yl_bottom = l_player + hpallet / 2;
	let yr_top = r_player - hpallet / 2;
	let yr_bottom = r_player + hpallet / 2;

	if (x_ball - ballRad <= wpallet
	&& y_ball >= yl_top && y_ball <= yl_bottom
	&& x_speed < 0)
	{
		x_speed *= -1;
	}
	else if (x_ball + ballRad >= w_canva - wpallet
	&& y_ball >= yr_top && y_ball <= yr_bottom
	&& x_speed > 0)
	{
		x_speed *= -1;
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
		red_display.classList.add('scored')
		setTimeout(() => {
			red_display.classList.remove('scored')
		}, 2000);
	if (red_score < 3)
		setTimeout(restart, 1000);
	else
		{
			document.getElementById("win").style.opacity = "1"
			document.getElementById("win").classList.add('blue_win')
			red_display.classList.add('final_score')
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
		blue_display.classList.add('scored')
		setTimeout(() => {
			blue_display.classList.remove('scored')
		}, 2000);
	if (blue_score < 3)
		setTimeout(restart, 1000);
	else
		{
			document.getElementById("win").style.opacity = "1"
			document.getElementById("win").classList.add('red_win')
			blue_display.classList.add('final_score')
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
	frame();
}, 5000);

document.addEventListener('keydown', (e)=>
{
	if (!stop && e.keyCode == 38 && (r_player - hpallet / 2) > 0)
		r_player -= 25;
	if (!stop && e.keyCode == 40 && (r_player + hpallet / 2) < h_canva)
		r_player += 25;

	if (!stop && e.keyCode == 90 && (l_player - hpallet / 2) > 0)
		l_player -= 25;
	if (!stop && e.keyCode == 83 && (l_player + hpallet / 2) < h_canva)
		l_player += 25;
})


