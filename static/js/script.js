async function scanWebsite() {

    const url = document.getElementById("urlInput").value;

    const loader = document.getElementById("loader");

    const resultBox = document.getElementById("resultBox");

    // VALIDATION

    if (url.trim() === "") {

        alert("Please enter a website URL");

        return;
    }

    // SHOW LOADER

    loader.style.display = "block";

    resultBox.innerHTML = "";

    try {

        const response = await fetch("/scan_url", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });

        const data = await response.json();

        // HIDE LOADER

        loader.style.display = "none";

        // RESULT CARD

        resultBox.innerHTML = `

            <div class="scan-result-card ${data.color}">

                <h2>
                    Scan Result
                </h2>

                <h3>
                    Status:
                    ${data.status}
                </h3>

                <h4>
                    Safety Score:
                    ${data.score}/100
                </h4>

                <h4>
                    Phishing Probability:
                    ${data.probability}%
                </h4>

                <div class="mt-4">

                    <h5>
                        Detection Reasons
                    </h5>

                    <ul>

                        ${data.reasons.map(reason =>
                            `<li>${reason}</li>`
                        ).join("")}

                    </ul>

                </div>

                <div class="mt-4">

                    <h5>
                        Recommendations
                    </h5>

                    <ul>

                        ${data.recommendations.map(rec =>
                            `<li>${rec}</li>`
                        ).join("")}

                    </ul>

                </div>

            </div>

        `;

    }

    catch (error) {

        loader.style.display = "none";

        resultBox.innerHTML = `

            <div class="alert alert-danger">

                Error scanning website.

            </div>

        `;

        console.log(error);
    }

}
const canvas = document.getElementById("cyberCanvas");
const ctx = canvas.getContext("2d");

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

let particles = [];
let lines = [];

class Particle {
    constructor() {
        this.x = Math.random() * canvas.width;
        this.y = Math.random() * canvas.height;
        this.radius = Math.random() * 2;
        this.speed = Math.random() * 0.5;
    }

    update() {
        this.y -= this.speed;
        if (this.y < 0) {
            this.y = canvas.height;
            this.x = Math.random() * canvas.width;
        }
    }

    draw() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
        ctx.fillStyle = "#00f7ff";
        ctx.fill();
    }
}

class Line {
    constructor(x, y) {
        this.x = x;
        this.y = y;
        this.length = Math.random() * 100 + 50;
        this.speed = Math.random() * 2 + 1;
    }

    update() {
        this.y -= this.speed;
        if (this.y < -this.length) {
            this.y = canvas.height;
        }
    }

    draw() {
        ctx.beginPath();
        ctx.moveTo(this.x, this.y);
        ctx.lineTo(this.x, this.y + this.length);
        ctx.strokeStyle = "rgba(0,247,255,0.4)";
        ctx.lineWidth = 1;
        ctx.shadowColor = "#00f7ff";
        ctx.shadowBlur = 10;
        ctx.stroke();
    }
}

// INIT
for (let i = 0; i < 150; i++) {
    particles.push(new Particle());
}

for (let i = 0; i < 80; i++) {
    lines.push(new Line(Math.random() * canvas.width, Math.random() * canvas.height));
}

// GRID FUNCTION
function drawGrid() {
    const spacing = 40;

    ctx.strokeStyle = "rgba(0,247,255,0.08)";
    ctx.lineWidth = 1;

    for (let x = 0; x < canvas.width; x += spacing) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
    }

    for (let y = 0; y < canvas.height; y += spacing) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
    }
}

// ANIMATION LOOP
function drawPerspectiveGrid() {
    const spacing = 40;
    const horizon = canvas.height * 0.6;

    ctx.strokeStyle = "rgba(0,247,255,0.08)";

    for (let i = 0; i < canvas.width; i += spacing) {
        ctx.beginPath();
        ctx.moveTo(canvas.width / 2, horizon);
        ctx.lineTo(i, canvas.height);
        ctx.stroke();
    }

    for (let j = 0; j < 20; j++) {
        let y = horizon + j * 20;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
    }
}

drawPerspectiveGrid();
// RESPONSIVE
window.addEventListener("resize", () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});