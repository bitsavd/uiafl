<script setup>
defineProps({
  label: String,
  value: [String, Number],
  hint: String,
  tone: { type: String, default: 'blue' },
})
</script>

<template>
  <div class="metric-card" :class="`tone-${tone}`">
    <span class="metric-accent"></span>
    <p>{{ label }}</p>
    <strong>{{ value ?? '-' }}</strong>
    <small>{{ hint }}</small>
  </div>
</template>
