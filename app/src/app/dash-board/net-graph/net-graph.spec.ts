import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NetGraph } from './net-graph';

describe('NetGraph', () => {
  let component: NetGraph;
  let fixture: ComponentFixture<NetGraph>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [NetGraph]
    })
    .compileComponents();

    fixture = TestBed.createComponent(NetGraph);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
