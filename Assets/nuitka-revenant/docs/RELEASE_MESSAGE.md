# Release message

## Versione italiana

Oggi rendo open source la seconda generazione del mio decompiler per Nuitka.

Non voglio presentarlo come uno strumento perfetto, perché non lo è. Voglio presentarlo per quello che è: anni di tentativi, errori, reverse engineering e notti passate a guardare machine code finché qualcosa che sembrava impossibile iniziava ad avere una forma.

La prima versione riusciva ad aprire il contenitore: recuperava costanti, moduli, metadati e altri artefatti. Questa nuova versione prova a fare il passo che mi interessava davvero: tornare dal codice nativo a un sorgente Python leggibile, in modalità statica, usando soltanto ciò che il binario può dimostrare.

In alcuni casi il risultato si avvicina molto alla struttura originale. In altri restano parti incomplete, rami complessi o espressioni che il compilatore ha trasformato troppo. Non voglio nasconderlo. Preferisco vedere un `pass`, un commento di incertezza o un audit onesto piuttosto che codice bello da vedere ma inventato.

Per me questo rilascio non riguarda soltanto Nuitka.

Ho iniziato a prendere sul serio il reverse engineering in un periodo della mia vita in cui mi sentivo chiuso fuori da quasi tutto. A scuola avevo vissuto bullismo, stanchezza e la sensazione continua di essere giudicato prima ancora di essere conosciuto. Essere autistico, troppo spesso, significava sentire altre persone parlare dei miei limiti invece di chiedermi cosa sapessi fare.

Per molto tempo il mio mondo è stato una stanza, un computer e internet. In sottofondo magari c'era hyperpop; qualche volta un FPS per staccare; poi tornavo davanti a un disassembly e provavo ancora. Il computer non mi chiedeva di sembrare normale. Il machine code non aveva pregiudizi. Era difficile, ma era onesto: da qualche parte nei byte esisteva una spiegazione.

Questa cosa mi ha salvato più volte di quanto riesca a spiegare.

Pubblico il codice perché non voglio che il reverse engineering rimanga una stanza chiusa, accessibile solo a chi ha soldi, contatti o conoscenze tenute segrete. Voglio rompere quella barriera. Voglio che un ragazzo curioso, magari solo davanti al proprio computer come lo ero io, possa aprire questo progetto, capire un pezzo in più e poi superarmi.

Non sto rilasciando un punto d'arrivo. Sto rilasciando una strada.

Se sei un reverser, provalo e rompilo. Se trovi un pattern che non capisce, portami un caso riproducibile. Se sai migliorarlo, fai una pull request. Se pensi che una parte sia sbagliata, dimostralo. È esattamente così che deve crescere un progetto del genere.

La conoscenza diventa più forte quando smette di avere paura di essere condivisa.

Questa è REVENANT.

— DimaReverse

## English version

Today I am open-sourcing the second generation of my Nuitka decompiler.

I will not call it perfect, because it is not. This release is years of attempts, mistakes, reverse engineering and nights spent staring at machine code until something that looked impossible slowly began to make sense.

The first version opened the container: it recovered constants, modules, metadata and other artifacts. This version takes the step I actually cared about — going from native code back to readable Python source, statically, using only evidence the binary can support.

Sometimes the result gets remarkably close to the original structure. Sometimes complex branches, optimized expressions or entire spans remain incomplete. I do not want to hide that. I would rather emit a `pass`, an uncertainty marker or an honest audit than source code that looks convincing but was invented.

For me, this release is about more than Nuitka.

I became serious about reverse engineering during a time when I felt locked out of almost everything. School had brought bullying, exhaustion and the constant feeling of being judged before being understood. Being autistic too often meant hearing other people describe my limits instead of asking what I could do.

For a long time, my world was a room, a computer and the internet. There might be hyperpop in the background, an FPS match when I needed my brain to go quiet, and then another disassembly to study. A computer did not ask me to look normal. Machine code had no prejudice. It was difficult, but it was honest: somewhere inside the bytes, there was an explanation.

That gave me something to hold on to.

I am releasing this because I do not want reverse engineering to remain a closed room, available only to people with money, connections or private knowledge. I want to break that barrier. I want a curious kid, maybe alone in front of a computer like I was, to open this project, understand one more thing, and eventually build something better than mine.

This is not an endpoint. It is a road I am opening.

If you are a reverser, test it and break it. If it misses a pattern, bring a reproducible case. If you can improve it, send a pull request. If you think something is wrong, prove it. That is exactly how this project should grow.

Knowledge becomes stronger when it stops being afraid of being shared.

This is REVENANT.

— DimaReverse

## Short launch post

I just open-sourced REVENANT, the second generation of my static Nuitka decompiler.

It reconstructs readable Python from Nuitka native binaries using constants, code objects, x86-64 analysis, source-line evidence and structured control flow. It is not perfect and it does not fake perfection: uncertain regions stay visible and every module gets an audit.

The first release unpacked Nuitka. This one tries to translate it back.

I built it through years of mistakes, isolation and stubborn curiosity. Now I want other reversers to break it, improve it and take it further than I could alone.

Reverse engineering should not be a closed room.

https://github.com/DimaReverse/nuitka-revenant
