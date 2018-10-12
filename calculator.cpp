// Some calculator code I wrote in undergrad in year 2000 or something.
// I have no idea how it works.

#include <stdio.h> 
#include <graphics.h> 
#include <dos.h> 
#include <stdlib.h> 
#include <math.h>

REGS r;

unsigned int & a = r.x.ax;
unsigned int & b = r.x.bx;
unsigned int & c = r.x.cx;
unsigned int & d = r.x.dx;

# define de 300 // Delay after pressing each key in ms

void main() {

  // Function Prototypes
  int bu();
  void str(int *p, int co2, int key);
  void cpy(int *p, int *q); // Copies Array p to Array q
  void res(int *p); // Resets The Dynamic Array
  void cl(); // Clears the Area where the Digits are Printed
  void wri(double equ, int *po); // Writes the Data on the Screen

  // Mathematical Functions

  int dotd(int *p); // Returns the Dot position in the Array From 0 to 11 .. 12 if no Dot
  double ar2di(int *y, int co2, int *po);
  double fmul(int *y, int size_y, int *z, int size_z, int *po);
  double fdiv(int *y, int size_y, int *z, int size_z, int *po);
  double fadd(int *y, int size_y, int *z, int size_z, int *po);
  double fsub(int *y, int size_y, int *z, int size_z, int *po);
  double fsqr(int *y, int size_y, int *po);
  double fexp(int *y, int size_y, int *z, int size_z, int *po);
  int ma(int a, int b);

  // Graphic Engine Started

  int gdriver = DETECT, gmode = 0;
  initgraph( & gdriver, & gmode, "c:\\");
  setcolor(1);
  rectangle(150, 30, 450, 400);
  rectangle(200, 90, 400, 120);
  int i, j = 150;

  setfillstyle(1, 8);
  floodfill(160, 190, 1);

  setcolor(15);
  outtextxy(280, 45, "Tyrax");
  outtextxy(230, 65, "email");

  setcolor(2);
  for (i = 170; i <= 270; i += 50)
  	rectangle(i, j, i + 30, j + 30);

  setfillstyle(1, 2);
  for (i = 180; i < 300; i += 50)
  	floodfill(i, 170, 2);

  setcolor(4);
  rectangle(350, 200, 380, 230);
  rectangle(400, 200, 430, 230);
  rectangle(350, 150, 430, 180);

  setfillstyle(1, 4);
  floodfill(400, 170, 4);
  floodfill(370, 220, 4);
  floodfill(420, 220, 4);

  setcolor(BLUE);
  rectangle(170, 200, 200, 230);
  rectangle(220, 200, 250, 230);
  rectangle(270, 200, 300, 230);

  for (j = 250; j <= 350; j += 50) {
    for (i = 170; i <= 270; i += 50) rectangle(i, j, i + 30, j + 30);
    for (i = 350; i <= 400; i += 50) rectangle(i, j, i + 30, j + 30);
  }

  setfillstyle(1, 1);
  for (i = 220; i < 380; i += 50)
    for (int l = 180; l < 300; l += 50)
      floodfill(l, i, 1);

  for (i = 270; i < 380; i += 50)
    for (l = 370; l < 440; l += 50)
      floodfill(l, i, 1);

  setcolor(15);
  outtextxy(182, 212, "7");
  outtextxy(182, 262, "4");
  outtextxy(182, 312, "1");
  outtextxy(182, 362, "0");
  outtextxy(232, 212, "8");
  outtextxy(232, 262, "5");
  outtextxy(232, 312, "2");
  outtextxy(232, 362, ".");
  outtextxy(282, 212, "9");
  outtextxy(282, 262, "6");
  outtextxy(282, 312, "3");
  outtextxy(273, 362, "exp");
  outtextxy(362, 262, "*");
  outtextxy(362, 312, "+");
  outtextxy(362, 362, "=");
  outtextxy(412, 262, "/");
  outtextxy(412, 312, "-");
  outtextxy(412, 362, "�");
  outtextxy(182, 162, "M");
  outtextxy(230, 162, "M+");
  outtextxy(280, 162, "M-");
  outtextxy(375, 162, "Exit");
  outtextxy(362, 212, "C");
  outtextxy(408, 212, "AC");

  a = 1;
  int86(0x33, & r, & r);

  a = 7;
  c = 150;
  d = 450;
  int86(0x33, & r, & r);

  a = 8;
  c = 30;
  d = 400;
  int86(0x33, & r, & r);

  setcolor(BROWN);
  setwritemode(0);

  /*Graphic Commands Finished */

  int key,	// Code of the button Pressed
  co = 0,	// Overflow Flag
  k = 300,	// X Position of the first Character Printed on Screen
  fl = 0,	// Dot Flag zero(if not Pressed)  one(if more than once)
  co2 = 0,	// Number of the Data's Stored in Array p or q
  			// (if Dot is not pressed it equals co else it is co+1)
    op = 0, // Operation flag (If it is the first number Entered it will be zero
			// if the second is Entered it will be one and if the operation is
			// finished and the result is printed to screen it will be 2)
    on = 0, //   Operation Number (Can be 15-16-17-18-20)
    size_y = 0, //   Size of The First Number
    size_z = 0, //   Size of The Second Number
    mem_size = 0, //   Size of Memory
    mf = 0; 	//   Memory Flag  ( If M is called it will be 1 else it will be 0

  int *p = (int *) malloc(11 *2); // Default   Storing Device
  int *y = (int *) malloc(11 *2); // Primary   Storing Device
  int *z = (int *) malloc(11 *2); // Secondary Storing Device
  int *m = (int *) malloc(11 *2); // Memory

  res(p);
  res(y);
  res(z);
  res(m); // P.Y.Z.M Reset

  char *x = NULL;

  int *po = 0;

  b = 0; // r.x.bx=0;
  a = 3; // r.x.ax=3;

  for (;;) { // Main LOOP
    key = 24;
    int86(0x33, & r, & r);
    if (b == 1) {
      key = bu();

      if (key == 13) {
        cl();
        res(p);
        k = 300;
        key = 24;
        mf = co = co2 = fl = 0;
        if (op == 1) {
          size_z = 0;
          res(z);
        } else {
          size_y = 0;
          res(y);
          on = 0;
        }
        delay(de);
      }

      if (key == 14) {
        res(p);
        res(y);
        res(z);
        res(m);
        cl();
        mf = mem_size = op = on = co = co2 = fl = size_y = size_z = 0;
        key = 24;
        k = 300;
        delay(de);
      }

      if (key == 22) {
        cpy(p, m);
        mem_size = co2;
        mf = 1;
        key = 24;
        delay(de);
      }

      if (key == 23) {
        res(m);
        cl();
        setcolor(LIGHTGRAY);
        outtextxy(210, 103, "Memory Cleared");
        mem_size = 0;
        setcolor(BROWN);
        op = 2;
        key = 24;
        k = 300;
        mf = 0;
        delay(de);
      }

      if (key == 21)
        if (mem_size != 0) {
          cl();
          res(p);
          cpy(m, p);
          co2 = mem_size;
          k = 300;
          for (int i = 0; i < mem_size; i++) {
            sprintf(x, "%d", *(m + i));
            if ( *(m + i) == 11) {
              outtextxy(k, 103, ".");
              k += 8;
            } else {
              outtextxy(k, 103, x);
              k += 8;
            }
          }
          mf = 1;
        }

      if ((key == 20)) {
        double equ = 0;
        equ = fsqr(p, co2, po);
        res(p);
        mf = on = fl = co2 = co = 0;
        cl();
        char *tt = NULL;
        k = 300;
        sprintf(tt, "%f", equ);
        outtextxy(k, 103, tt);
        res(y);
        size_y = 0;
        res(z);
        size_z = 0;
        key = 24;
        op = 2;
        k = 300;
        delay(de);
      }

      if ((key > 14) && (key < 19) || (key == 12))
        if (op == 0) {
          cpy(p, y);
          res(p);
          op = 1; //Reseting all the Flags
          on = key;
          size_y = co2;
          mf = fl = co2 = co = 0;
          key = 24;
          k = 300;
          cl();
          delay(de);
        } //Waiting for the Second Number to be Entered

      if ((key == 19) && (op == 1) && (on != 16)) {
        cpy(p, z);
        op = 2;
        double equ;
        size_z = co2;
        if (on == 15) equ = fmul(y, size_y, z, size_z, po);
        if (on == 17) equ = fadd(y, size_y, z, size_z, po);
        if (on == 18) equ = fsub(y, size_y, z, size_z, po);
        if (on == 12) equ = fexp(y, size_y, z, size_z, po);
        on = fl = co = co2 = 0;
        k = 300;
        wri(equ, po);
        size_y = size_z = 0;
        *po = 0;
        res(p);
        res(y);
        res(z);
        key = 24;
        delay(de);
      }

      if ((key == 19) && (op == 1) && (on == 16)) {
        cpy(p, z);
        op = 2;
        double equ;
        size_z = co2;
        equ = fdiv(y, size_y, z, size_z, po);
        on = fl = co = co2 = 0;
        k = 300;
        wri(equ, po);
        size_y = size_z = 0;
        *po = 0;
        res(p);
        res(y);
        res(z);
        key = 24;
        delay(de);
      }

      if ((key > 0) && (key < 12) && (mf == 0)) {
        if (op == 2) {
          op = 0;
          cl();
        } // The First Number After another Calculation (So the Screen will be Cleaned with the First Digit Clicked
        if (key == 10) key = 0;
        str(p, co2, key);
        co++;
        co2++;
        if (co > 10) {
          setcolor(LIGHTGRAY);
          outtextxy(210, 103, "Overflow");
        } else {
          sprintf(x, "%d", key);
          if ((key == 11) && (fl == 1)) {
            co--;
            co2--;
            outtextxy(k, 103, "");
            k -= 8;
          } // More than Once It Won't
          if ((key == 11) && (fl == 0)) {
            co--;
            outtextxy(k, 103, ".");
            fl = 1;
          } // Dot pressed for the First Time it will be Printed
          if (key != 11) outtextxy(k, 103, x);
          k += 8;
          key = 24;
          delay(de);
        }
        if (key == 0) key = 24;

      }

      if (key == 0) {
        p = y = z = m = NULL;
        exit(0);
      } //Exit Key Pressed
    }
  }
}

int bu() {
  if ((c > 170) && (c < 200) && (d > 300) && (d < 330)) return (1); // One
  if ((c > 220) && (c < 250) && (d > 300) && (d < 330)) return (2); // Two
  if ((c > 270) && (c < 300) && (d > 300) && (d < 330)) return (3); // Three
  if ((c > 170) && (c < 200) && (d > 250) && (d < 280)) return (4); // Four
  if ((c > 220) && (c < 250) && (d > 250) && (d < 280)) return (5); // Five
  if ((c > 270) && (c < 300) && (d > 250) && (d < 280)) return (6); // Six
  if ((c > 170) && (c < 200) && (d > 200) && (d < 230)) return (7); // Seven
  if ((c > 220) && (c < 250) && (d > 200) && (d < 230)) return (8); // Eight
  if ((c > 270) && (c < 300) && (d > 200) && (d < 230)) return (9); // Nine
  if ((c > 170) && (c < 200) && (d > 350) && (d < 380)) return (10); // Zero
  if ((c > 220) && (c < 250) && (d > 350) && (d < 380)) return (11); // Dot
  if ((c > 270) && (c < 300) && (d > 350) && (d < 380)) return (12); // Exp
  if ((c > 350) && (c < 380) && (d > 200) && (d < 230)) return (13); // C
  if ((c > 350) && (c < 380) && (d > 250) && (d < 280)) return (15); // Multiply
  if ((c > 350) && (c < 380) && (d > 300) && (d < 330)) return (17); // Add
  if ((c > 350) && (c < 380) && (d > 350) && (d < 380)) return (19); // Equals
  if ((c > 400) && (c < 430) && (d > 200) && (d < 230)) return (14); // AC
  if ((c > 400) && (c < 430) && (d > 250) && (d < 280)) return (16); // Divide
  if ((c > 400) && (c < 430) && (d > 300) && (d < 330)) return (18); // Minus
  if ((c > 400) && (c < 430) && (d > 350) && (d < 380)) return (20); // Square Root
  if ((c > 170) && (c < 200) && (d > 150) && (d < 180)) return (21); // M
  if ((c > 220) && (c < 250) && (d > 150) && (d < 180)) return (22); // M+
  if ((c > 270) && (c < 300) && (d > 150) && (d < 180)) return (23); // M-
  if ((c > 350) && (c < 430) && (d > 150) && (d < 180)) return (0);  // Exit

  return (24); // Nothing pressed
}

void str(int *p, int co2, int key) { // Stores the Number in the Array
  *(p + co2) = key;
}

void cpy(int *p, int *q) {
  for (int i = 0; i < 12; i++) *(q + i) = *(p + i);
}

void res(int *p) {
  for (int i = 0; i < 12; i++) *(p + i) = 0;
}

void cl() {
  setfillstyle(1, 0);
  floodfill(310, 104, 1);
}

int dotd(int *p) {
  for (int i = 0; i < 12; i++)
    if ( *(p + i) == 11) return (i);
  return (12);
}

double ar2di(int *p, int co2, int *po) {

  *po = 0;
  int *a = (int *) malloc(11 *2);
  res(a);
  cpy(p, a);
  int dp = dotd(p);
  for (int i = dp; i < co2 + 1; i++) *(a + i) = *(p + i + 1);
  double z = 0;
  for (i = 0; i < co2 + 1; i++) z += (*(a + i) *pow(10, co2 - 1 - i));
  int power = co2 - dp;
  if (dp == 12) power = 0;
  z = z * pow(10, -power);
  *po = power;
  return (z);
}

int mx(int a, int b) {
  if (a > b) return (a);
  else return (b);
}

void wri(double equ, int *po) {

  cl();
  char *x = NULL;
  int k = 300;
  double temp = 0;
  int *te = (int *) malloc(11 * 2);
  int *t = (int *) malloc(11 * 2);
  res(t);
  temp = equ *pow10( *po);
  int cl = 0;
  if (temp < 0) cl = 1;
  temp = abs(temp);
  int d = 0;
  if (temp != 0) d = log10(temp) + 1;
  else d = 1;
  if (d > 10) {
    temp = floor(temp / pow10(10));
    d = 10;
  }
  int t1 = 0, t2 = 0;
  for (int i = d; i > 0; i--) {
    t1 = temp / pow10(i - 1);
    t2 = (floor(temp / pow10(i)) *10);
    *(t + i) = t1 - t2;
  }
  int ad = *po - 1;
  cpy(t, te);
  *(te + ad) = 11;
  for (i = ad; i >= 0; i--) *(te + i - 1) = *(t + i);
  int s = 0;
  s = *(te + ad);
  *(te + ad) = *(te + ad + 1);
  *(te + ad + 1) = s;
  if (cl == 1) {
    outtextxy(k, 103, "-");
    k += 8;
  }

  for (i = d; i > 0; i--) {
    sprintf(x, "%d", *(te + i));
    if ( *(te + i) == 11) {
      outtextxy(k, 103, ".");
      k += 8;
    }
    if ( *(te + i) != 11) {
      outtextxy(k, 103, x);
      k += 8;
    }
  }
}

double fadd(int *y, int size_y, int *z, int size_z, int *po) {
  *po = 0;
  int po1 = 0, po2 = 0;
  double di1 = ar2di(y, size_y, & po1),
  di2 = ar2di(z, size_z, & po2);
  *po = mx(po1, po2);
  return (di1 + di2);
}

double fsub(int *y, int size_y, int *z, int size_z, int *po) {
  *po = 0;
  int po1 = 0, po2 = 0;
  double di1 = ar2di(y, size_y, & po1),
  di2 = ar2di(z, size_z, & po2);
  *po = mx(po1, po2);
  return (di1 - di2);
}

double fmul(int *y, int size_y, int *z, int size_z, int *po) {
  *po = 0;
  int po1 = 0, po2 = 0;
  double di1 = ar2di(y, size_y, & po1),
  di2 = ar2di(z, size_z, & po2);
  *po = po1 + po2;
  return (di1 *di2);
}

double fdiv(int *y, int size_y, int *z, int size_z, int *po) {
  int po1, po2;
  double di1 = ar2di(y, size_y, & po1),
  di2 = ar2di(z, size_z, & po2);
  *po = 10 - (size_y + size_z);
  if (di2 == 0) return (0);
  return (di1 / di2);
}

double fsqr(int *y, int size_y, int *po) {
  double di = ar2di(y, size_y, po);
  return sqrt(di);
}

double fexp(int *y, int size_y, int *z, int size_z, int *po) {
  int po1 = 0, po2 = 0;
  double di = ar2di(y, size_y, & po1);
  int di2 = ar2di(z, size_z, & po2);
  double di3 = 0;
  di3 = di *pow10(di2);
  *po = po1 - di2;
  if ( *po <= 0) *po = 0;
  return (di3);
}