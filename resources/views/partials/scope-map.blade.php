{{-- Decorative dotted network map (design.md §5.16). The arcs draw in once on load. --}}
<svg class="scope-map" viewBox="0 0 480 300" preserveAspectRatio="xMidYMid slice" aria-hidden="true" focusable="false">
    <defs>
        <pattern id="dots-{{ $uid ?? 'm' }}" width="16" height="16" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1.1" fill="var(--line-strong)"/></pattern>
        <radialGradient id="fade-{{ $uid ?? 'm' }}"><stop offset="0.55" stop-color="#fff"/><stop offset="1" stop-color="#000"/></radialGradient>
        <mask id="mask-{{ $uid ?? 'm' }}"><rect width="480" height="300" fill="url(#fade-{{ $uid ?? 'm' }})"/></mask>
    </defs>
    <rect width="480" height="300" fill="url(#dots-{{ $uid ?? 'm' }})" mask="url(#mask-{{ $uid ?? 'm' }})"/>
    <g fill="none" stroke="var(--accent)" stroke-width="1" stroke-linecap="round" opacity=".7">
        <path class="arc" style="--d:0" d="M120 190 C 170 90, 260 80, 330 120" pathLength="1"/>
        <path class="arc" style="--d:1" d="M330 120 C 360 170, 340 220, 300 238" pathLength="1"/>
        <path class="arc" style="--d:2" d="M120 190 C 160 250, 240 262, 300 238" pathLength="1"/>
    </g>
    <g>
        <circle cx="120" cy="190" r="14" fill="var(--accent-glow)"/><circle cx="120" cy="190" r="4" fill="var(--accent)"/>
        <circle cx="330" cy="120" r="14" fill="var(--accent-glow)"/><circle cx="330" cy="120" r="4" fill="var(--accent)"/>
        <circle cx="300" cy="238" r="14" fill="var(--accent-glow)"/><circle cx="300" cy="238" r="4" fill="var(--accent)"/>
    </g>
</svg>
