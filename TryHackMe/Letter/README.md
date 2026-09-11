# Letter - TryHackMe Challenge Notes

**Category:** OSINT  
**Platform:** TryHackMe  

---

## Challenge Overview & Artifacts

The **Letter** challenge provides three primary artifacts discovered in an attic:
1. **`letter.png`**: A weathered envelope addressed to "Édouard G..." with a reference to the **SNSM** (*Société Nationale de Sauvetage en Mer* — the French National Sea Rescue Society) and an orange postal barcode along the bottom margin.
2. **`Newspaper_clipping.png`**: A vintage newspaper clipping from the French daily newspaper **L'Ouest-Éclair** featuring headlines:
   - *"L'œuvre urgente"*
   - *"Une catastrophe sur les côtes du Finistère"*
   - *"Amundsen a-t-il atteint le pôle Nord?"*
   - *"Les événements du Maroc - M. Herriot se déclare solidaire de M. Painlevé"*
3. **`Note.txt`**: A handwritten letter transcript from Audette:
   > *"Mon cher Édouard,*  
   > *Aujourd'hui, en rangeant le grenier chez mes grands-parents, je suis tombée sur cette vieille coupure de journal. Ton arrière-grand-père n'avait même pas l'âge de passer le permis quand il s'est distingué ce jour-là. Le benjamin de l'équipe, et certainement pas le moins courageux.*  
   > *Il serait si fier de te voir sur l'eau à ton tour.*  
   > *Avec toute mon affection,*  
   > *Audette"*

---

## Investigation Angles & Clues

- **Historical Date Corroboration:** The newspaper mentions Roald Amundsen's North Pole expedition and politicians Édouard Herriot / Paul Painlevé (dating the event around May 1925). The BnF (Bibliothèque nationale de France) / Gallica archives host digitized copies of *L'Ouest-Éclair*.
- **Location & Incident:** Finistère coastal maritime rescue / shipwreck incident involving young lifeboat crew members.
- **Envelope Barcode Decoding:** The orange postal barcode on French "Lettre Verte" mail encodes French postal sorting and routing codes.
