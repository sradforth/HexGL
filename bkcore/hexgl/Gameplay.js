 /*
 * HexGL
 * @author Thibaut 'BKcore' Despoulain <http://bkcore.com>
 * @license This work is licensed under the Creative Commons Attribution-NonCommercial 3.0 Unported License. 
 *          To view a copy of this license, visit http://creativecommons.org/licenses/by-nc/3.0/.
 */

var bkcore = bkcore || {};
bkcore.hexgl = bkcore.hexgl || {};

bkcore.hexgl.Gameplay = function(opts)
{
	var self = this;

	this.startDelay = opts.hud == null ? 0 : 1000;
	this.countDownDelay = opts.hud == null ? 1000 : 1500;

	this.active = false;
	this.timer = new bkcore.Timer();
	this.modes = {
		'timeattack':null,
		'survival':null,
		'replay':null
	};
	this.mode = opts.mode == undefined || !(opts.mode in this.modes) ? "timeattack" : opts.mode;
	this.step = 0;

	this.hud = opts.hud;
	this.shipControls = opts.shipControls;
	this.cameraControls = opts.cameraControls;
	this.track = opts.track;
	this.analyser = opts.analyser;
	this.pixelRatio = opts.pixelRatio;

	this.previousCheckPoint = -1;

	this.results = {
		FINISH: 1,
		DESTROYED: 2,
		WRONGWAY: 3,
		REPLAY: 4,
		NONE: -1
	};
	this.result = this.results.NONE;

	this.lap = 1;
	this.lapTimes = [];
	this.lapTimeElapsed = 0;
	this.maxLaps = 2;
	this.score = null;
	this.dnf = false;
	this.finishTime = null;
	this.onFinish = opts.onFinish == undefined ? function(){console.log("FINISH");} : opts.onFinish;

	this.raceData = null;

	this.modes.timeattack = function()
	{
		self.raceData.tick(this.timer.time.elapsed);

		self.hud != null && self.hud.updateTime(self.timer.getElapsedTime());
		var cp = self.checkPoint();

		if(cp == self.track.checkpoints.start && self.previousCheckPoint == self.track.checkpoints.last)
		{
			self.previousCheckPoint = cp;
			var t = self.timer.time.elapsed;
			self.lapTimes.push(t - self.lapTimeElapsed);
			self.lapTimeElapsed = t;

			if(self.lap == this.maxLaps)
			{
				self.end(self.results.FINISH);
			}
			else
			{
				self.lap++;
				self.hud != null && self.hud.updateLap(self.lap, self.maxLaps);

				if(self.lap == self.maxLaps)
					self.hud != null && self.hud.display("Final lap", 0.5);
			}
		}
		else if(cp != -1 && cp != self.previousCheckPoint)
		{
			self.previousCheckPoint = cp;
			//self.hud.display("Checkpoint", 0.5);
		}

		if(self.shipControls.destroyed == true)
		{
			self.end(self.results.DESTROYED);
		}
	};

	this.modes.replay = function()
	{
		self.raceData.applyInterpolated(this.timer.time.elapsed);

		if(self.raceData.seek == self.raceData.last)
		{
			self.end(self.result.REPLAY);
		}
	};
}

bkcore.hexgl.Gameplay.prototype.simu = function()
{
	this.lapTimes = [92300, 91250, 90365];
	this.finishTime = this.lapTimes[0]+this.lapTimes[1]+this.lapTimes[2];
	if(this.hud != null) this.hud.display("Finish");
	this.step = 100;
	this.result = this.results.FINISH;
	this.shipControls.active = false;
}

var cm_client;

bkcore.hexgl.Gameplay.prototype.start = function(opts)
{

	var that = this;

	this.dnf = false;

	var params =
	{
		//coinmode_api_server : "http://localhost:3000", // Useful for pointing to a different CoinMode API server.  If not set it will send all API calls to https://api.coinmode.com
		//session_token : "st_PQnD54nPaG2g", // If we already have a session token they are trying to jump to, use this.  (I.e. the player has been assigned to an existing round and session already)
		//uuid_or_email: "password0@radforth.com", // This is the login token if it already exists.  If it doesn't exist the user will be invited to log in.#
		game_id: "84", // This is the game we are looking to play.  This is required for getting the play_token phase or creating new rounds
		game_name: "HexGL", // This is the game we are looking to play.  This is required for getting the play_token phase or creating new rounds
		call_session_start_from_client: true,	// If a single player game we can get this browser to invoke the session has started.  When doing multiplayer games it is best the server calls /session/start so it starts all players at the same time and can refund if there is an error.
		skip_start_screen : true, // This jumps straight into the game rather than showing the 'Play!' screen
		request_permissions : "permission_charge_to_play,permission_phone,permission_charge_iap",
		allow_topup_page: true, // If the user requires more funds to play, show the topup page
		show_locked_rounds: true, // 
		newround_passphrase_allow_user_entered : false, // Default is false and a random one is created each time so can only be joined by sharing invites.
		// newround_allow_empty_passphrase : true, // If a blank passphrase can be used (i.e. a public game), default false.
		//play_token:"st_PQnD54nPaG2g" // Use a playtoken as the voucher to obtain the session token for playing a game.  If not set it will ask the user to create an account or authorise a new playtoken for this game.	
		auto_create_new_round_if_none_found : false, // If there were no rounds found automatically jump to the create a new round?
		allow_create_round : false, // On the round searching screen, if this is set to false the 'create round' button is hidden
		show_winnings : false, // If false this shows the score being submitted, if true it shows the paid out amounts (This is only possible if the round has finished, i.e. a server game where the entire round has ended as this game ended)
		testnet: true,
	}
	
	// Parameters that may be part of the GET URL are session_token, round_id, passphrase
//alert("SR: In gameplaystart");
debugger;
	cm_client = new CoinModeClient( params, function on_start( err )
		{
			console.log("Init_game()");
		}
	);
	// Show coinmode popup to get the session token to play the game.
	cm_client.setup( function( err, array_details ) 
		{						
			console.log(array_details);
			/*
			{		
				display_name:"bob",
				round_id:17, 
				session_token:"st_2iuDb2kAvzhC"
			}
			*/
			if( err )
			{
				alert("User cancelled");
				allow_start = true;
				$('#intro').fadeIn();
			}
			else
			{
				//on_round_selected( array_details );
				var player_name = "(new)"; // Could do an API call to Coinmode to obtain player info or when they've logged in.
				player_name = cm_client.get_display_name("Not logged in");
				if( array_details['round_id'] > 0 )
				{
					// Call this when the game is playing the selected round/session
					cm_client.session_start( function( err2 ) 
						{
							if( err2 )
							{
								console.log("Error");
								console.log(err2);
								alert("Unable to join round.  Your time will not be couunted.  Please reload the game to try again:"+err2);
							}
							that.init_game(opts);
						}
					);
				}
				else
				{
					alert("Invalid round found. Aborting");
				}

			}
		}
	);


}
	
	
	
	
	
bkcore.hexgl.Gameplay.prototype.init_game = function(opts)
{

	this.finishTime = null;
	this.score = null;
	this.lap = 1;

	this.shipControls.reset(this.track.spawn, this.track.spawnRotation);
	this.shipControls.active = false;

	this.previousCheckPoint = this.track.checkpoints.start;

	this.raceData = new bkcore.hexgl.RaceData(this.track.name, this.mode, this.shipControls);
	if(this.mode == 'replay')
	{
		this.cameraControls.mode = this.cameraControls.modes.ORBIT;
		if(this.hud != null) this.hud.messageOnly = true;

		try {
			var d = localStorage['race-'+this.track.name+'-replay'];
			if(d == undefined)
			{
				console.error('No replay data for '+'race-'+this.track.name+'-replay'+'.');
				return false;
			}
			this.raceData.import(
				JSON.parse(d)
			);
		}
		catch(e) { console.error('Bad replay format : '+e); return false; }
	}

	this.active = true;
	this.step = 0;
	this.timer.start();
	if(this.hud != null)
	{
		this.hud.resetTime();
		this.hud.display("Get ready", 1);
		this.hud.updateLap(this.lap, this.maxLaps);
	}
}

bkcore.hexgl.Gameplay.prototype.end = function(result)
{
	this.score = this.timer.getElapsedTime();
	this.finishTime = this.timer.time.elapsed;
	this.timer.start();
	this.result = result;

	this.shipControls.active = false;

	var longest_time = 10*60*1000; // 5 mins is max time.
	var local_score = longest_time - this.finishTime;
	if( local_score < 0 )
	{
		local_score = 0;
	}
	
	if(result == this.results.FINISH)
	{
		if(this.hud != null) this.hud.display("Finish");
		this.step = 100;
	}
	else if(result == this.results.DESTROYED)
	{
		if(this.hud != null) this.hud.display("Destroyed");
		this.step = 100;
		this.dnf = true;
		local_score = 5;
//		alert("SR: DNF.  Submitting Coinmode score of:"+this.finishTime );
	}
	//alert("SR: YES, Finished.  Submitting Coinmode score of:"+score );
	cm_client.session_stop( {"score":local_score, dnf:this.dnf}, function(err)
		{
			if( err )
			{
				console.log( err );
				alert("Error submitting result:"+err);
			}
			// Completed
			cm_client.show_summary( function(err)
				{
					//alert("SR:Success");
					console.log("Success");
				}
			);
		}
	);
}

bkcore.hexgl.Gameplay.prototype.update = function()
{
	if(!this.active) return;

	this.timer.update();
	
	if(this.step == 0 && this.timer.time.elapsed >= this.countDownDelay+this.startDelay)
	{
		if(this.hud != null) this.hud.display("3");
		this.step = 1;
	}
	else if(this.step == 1 && this.timer.time.elapsed >= 2*this.countDownDelay+this.startDelay)
	{
		if(this.hud != null) this.hud.display("2");
		this.step = 2;
	}
	else if(this.step == 2 && this.timer.time.elapsed >= 3*this.countDownDelay+this.startDelay)
	{
		if(this.hud != null) this.hud.display("1");
		this.step = 3;
	}
	else if(this.step == 3 && this.timer.time.elapsed >= 4*this.countDownDelay+this.startDelay)
	{
		if(this.hud != null) this.hud.display("Go", 0.5);
		this.step = 4;
		this.timer.start();
		
		if(this.mode != "replay")
			this.shipControls.active = true;
	}
	else if(this.step == 4)
	{
		this.modes[this.mode].call(this);
	}
	else if(this.step == 100 && this.timer.time.elapsed >= 2000)
	{
		this.active = false;
		this.onFinish.call(this);
	}
}

bkcore.hexgl.Gameplay.prototype.checkPoint = function()
{
	var x = Math.round(this.analyser.pixels.width/2 + this.shipControls.dummy.position.x * this.pixelRatio);
	var z = Math.round(this.analyser.pixels.height/2 + this.shipControls.dummy.position.z * this.pixelRatio);

	var color = this.analyser.getPixel(x, z);

	if(color.r == 255 && color.g == 255 && color.b < 250)
		return color.b;
	else
		return -1;
}