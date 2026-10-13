# Conjunto etiquetado

Mide cada cambio en las reglas o en `lib/review.js` con dos preguntas: ¿queda ruido? y ¿se sigue
detectando lo malicioso?

- `test/helpers/malware.js`: repos maliciosos de prueba (técnicas reales e intentos de colarse
  por las rebajas de gravedad). No hay malware de verdad: todo apunta a `evil.example` y nada se
  ejecuta. `npm test` los comprueba con el analizador de JavaScript y sin él.
- `labels.json`: avisos de repos reales revisados a mano. `real` tiene que salir al menos con
  `min` (y como mucho `max`, si lo lleva); `ruido` no puede pasar de `max`. `rule` y `file` son
  expresiones regulares; `why` explica la decisión.
- `score.js`: puntúa una tanda (`npm run gold -- <carpeta con los JSON>`) y lista al final las
  amenazas medias o más que aún no tienen etiqueta.

## Cuando aparece un falso positivo

1. Etiquetarlo en `labels.json` con el porqué.
2. Si el arreglo rebaja algo, añadir en `test/helpers/malware.js` la muestra que intentaría
   colarse por esa rebaja (tiene que seguir saliendo alta).
3. `npm test`, y después una tanda con `npm run gold`.
