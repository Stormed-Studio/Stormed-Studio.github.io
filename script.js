const canvas = document.getElementById("snow");
const ctx = canvas.getContext("2d");

const prefersReducedMotion = window.matchMedia(
  "(prefers-reduced-motion: reduce)"
).matches;

const settings = {
  density: prefersReducedMotion ? 0.00008 : 0.00018,
  speedScale: prefersReducedMotion ? 0.35 : 1,
  minRadius: 0.8,
  maxRadius: 2.2,
  minLife: 6,
  maxLife: 14
};

let width = 0;
let height = 0;
let dpr = 1;
let maxParticles = 0;
const particles = [];

const rand = (min, max) => min + Math.random() * (max - min);

function makeParticle(randomY) {
  const life = rand(settings.minLife, settings.maxLife);
  return {
    x: rand(0, width),
    y: randomY ? rand(0, height) : rand(-height * 0.2, 0),
    r: rand(settings.minRadius, settings.maxRadius),
    speed: rand(14, 40) * settings.speedScale,
    drift: rand(-12, 12) * settings.speedScale,
    sway: rand(6, 18),
    swaySpeed: rand(0.6, 1.6),
    age: rand(0, life),
    life,
    seed: Math.random() * Math.PI * 2
  };
}

function respawn(particle) {
  const next = makeParticle(false);
  Object.assign(particle, next);
}

function resize() {
  width = window.innerWidth;
  height = window.innerHeight;
  dpr = Math.min(2, window.devicePixelRatio || 1);

  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;

  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  maxParticles = Math.max(80, Math.floor(width * height * settings.density));
  while (particles.length < maxParticles) {
    particles.push(makeParticle(true));
  }
  if (particles.length > maxParticles) {
    particles.length = maxParticles;
  }

  ctx.shadowBlur = 10;
  ctx.shadowColor = "rgba(160, 210, 255, 0.45)";
  ctx.fillStyle = "#ffffff";
}

let lastTime = performance.now();

function tick(now) {
  const dt = Math.min(0.033, (now - lastTime) / 1000);
  lastTime = now;

  ctx.clearRect(0, 0, width, height);

  for (const particle of particles) {
    particle.age += dt;
    if (particle.age >= particle.life) {
      respawn(particle);
    }

    const t = particle.age / particle.life;
    const alpha = Math.sin(Math.PI * t);
    const swayX = Math.sin(now * 0.001 * particle.swaySpeed + particle.seed);

    particle.x += (particle.drift + swayX * 0.8) * dt;
    particle.y += particle.speed * dt;

    if (
      particle.y > height + 20 ||
      particle.x < -40 ||
      particle.x > width + 40
    ) {
      respawn(particle);
      particle.y = rand(-height * 0.2, 0);
    }

    ctx.globalAlpha = alpha;
    ctx.beginPath();
    ctx.arc(particle.x, particle.y, particle.r, 0, Math.PI * 2);
    ctx.fill();
  }

  ctx.globalAlpha = 1;
  requestAnimationFrame(tick);
}

resize();
window.addEventListener("resize", resize, { passive: true });
requestAnimationFrame(tick);
